#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include "main.hpp"
#include "common.hpp"
#include "analyzer.hpp"
#include "encrypter.hpp"
#include "pe_modifier.hpp"
#include "loader_stub_config.hpp"

FILE* logFile = NULL;

void logf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    vprintf(fmt, args);

    if (logFile) {
        va_list args_copy;
        va_copy(args_copy, args);
        vfprintf(logFile, fmt, args_copy);
        fflush(logFile);
        va_end(args_copy);
    }
    va_end(args);
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        yapBad("Usage: %s <input_pe_file> <output_encrypted_intermediate_file> <output_final_packed_file> <log_filename>", argv[0]);
        return -1;
    }

    const char* inputFile = argv[1];
    const char* encryptedIntermediateFile = argv[2];
    const char* finalPackedFile = argv[3];
    const char* logFileName = argv[4];

    logFile = fopen(logFileName, "w");
    if (!logFile) {
        printf("[*_*] FATAL: Can't open log file: %s. Aborting.\n", logFileName);
        return -1;
    }

    logf("[INFO] Crypter started.\n");
    logf("[INFO] Input PE: %s\n", inputFile);
    logf("[INFO] Intermediate Encrypted Output: %s\n", encryptedIntermediateFile);
    logf("[INFO] Final Packed Output: %s\n", finalPackedFile);
    logf("[INFO] Log File: %s\n\n", logFileName);

    if (!analyzer_main(inputFile)) {
        logf("[ERROR] Failed to analyze input file: %s\n", inputFile);
        if (logFile) fclose(logFile);
        return -1;
    }
    logf("[SUCCESS] Analyzed input file: %s successfully.\n\n", inputFile);

    BYTE* bufferFromEncrypter = nullptr;
    DWORD sizeOfBufferFromEncrypter = 0;
    BYTE encryptionKey = 'a';

    if (!encrypter_main(inputFile, encryptedIntermediateFile, encryptionKey, &bufferFromEncrypter, &sizeOfBufferFromEncrypter)) {
        logf("[ERROR] encrypter_main failed for input: %s\n", inputFile);
        if (logFile) fclose(logFile);
        return -1;
    }
    logf("[SUCCESS] encrypter_main completed. In-memory buffer @ 0x%p, Size: %lu bytes.\n\n ", (void*)bufferFromEncrypter, sizeOfBufferFromEncrypter);

    if (bufferFromEncrypter == nullptr || sizeOfBufferFromEncrypter == 0) {
        logf("[ERROR] encrypter_main did not return a valid buffer or size.\n");
        if (logFile) fclose(logFile);
        return -1;
    }

	logf("-- Preparing loader metadata for the packed PE.\n");

    LoaderMetadata loaderMeta;
    memset(&loaderMeta, 0, sizeof(LoaderMetadata));

    PIMAGE_NT_HEADERS_CURRENT pNtHeadersForMetadata = GetNtHeadersFromBuffer(bufferFromEncrypter);
    if (!pNtHeadersForMetadata) {
        logf("[ERROR] Failed to get NT Headers from the buffer returned by encrypter_main. Cannot prepare loader metadata.\n");
        HeapFree(GetProcessHeap(), 0, bufferFromEncrypter);
        if (logFile) fclose(logFile);
        return -1;
    }

    loaderMeta.originalOepRva = pNtHeadersForMetadata->OptionalHeader.AddressOfEntryPoint;
    loaderMeta.decryptionKey = encryptionKey;
    loaderMeta.hookMarker = 0xDEADBEEF;

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeadersForMetadata);
    for (WORD i = 0; i < pNtHeadersForMetadata->FileHeader.NumberOfSections; ++i, ++pSection) {
        if (strncmp((char*)pSection->Name, ".text", 5) == 0) {
            loaderMeta.textSectionRva = pSection->VirtualAddress;
            loaderMeta.textSectionVirtualSize = pSection->Misc.VirtualSize;
            logf("[+] LoaderMetadata: .text section RVA=0x%X, VirtualSize=0x%X\n", loaderMeta.textSectionRva, loaderMeta.textSectionVirtualSize);
        }
        else if (strncmp((char*)pSection->Name, ".rdata", 6) == 0) {
            loaderMeta.rdataSectionRva = pSection->VirtualAddress;
            loaderMeta.rdataSectionVirtualSize = pSection->Misc.VirtualSize;
            logf("[+] LoaderMetadata: .rdata section RVA=0x%X, VirtualSize=0x%X\n", loaderMeta.rdataSectionRva, loaderMeta.rdataSectionVirtualSize);
        }
        else if (strncmp((char*)pSection->Name, ".data", 5) == 0) {
			loaderMeta.dataSectionRva = pSection->VirtualAddress;
			loaderMeta.dataSectionVirtualSize = pSection->Misc.VirtualSize;
			logf("[+] LoaderMetadata: .data section RVA=0x%X, VirtualSize=0x%X\n", loaderMeta.dataSectionRva, loaderMeta.dataSectionVirtualSize);
		}
    }
    if (loaderMeta.textSectionRva == 0)
        logf("[WARNING] .text section RVA not found for LoaderMetadata. Stub might not work correctly.\n");

    logf("[SUCCESS] LoaderMetadata prepared. OriginalOEP RVA: 0x%X, DecryptionKey: 0x%02X.\n\n", loaderMeta.originalOepRva, loaderMeta.decryptionKey);

    DWORD finalPackedPEFileSize = sizeOfBufferFromEncrypter;
    DWORD loaderStubRva = 0;
    BYTE* finalPackedPEBuffer = nullptr;

    logf("-- Attempting to add loader section to the in-memory PE (current size: %lu bytes).\n", finalPackedPEFileSize);
    finalPackedPEBuffer = AddLoaderSectionToPE(bufferFromEncrypter, &finalPackedPEFileSize, &loaderMeta, &loaderStubRva);

    HeapFree(GetProcessHeap(), 0, bufferFromEncrypter);
    bufferFromEncrypter = nullptr;

    if (!finalPackedPEBuffer) {
        logf("[ERROR] AddLoaderSectionToPE failed.\n");
        if (logFile) fclose(logFile);
        return -1;
    }
    logf("[SUCCESS] AddLoaderSectionToPE completed. New PE size: %lu bytes. Loader Stub RVA: 0x%X.\n\n", finalPackedPEFileSize, loaderStubRva);


    PIMAGE_NT_HEADERS_CURRENT pFinalPackedNtHeaders = GetNtHeadersFromBuffer(finalPackedPEBuffer);
    if (!pFinalPackedNtHeaders) {
        logf("[ERROR] Failed to get NT Headers from the final packed PE buffer.\n");
        free(finalPackedPEBuffer);
        if (logFile) fclose(logFile);
        return -1;
    }

    logf("[INFO] Original EntryPoint was RVA: 0x%X.\n", pFinalPackedNtHeaders->OptionalHeader.AddressOfEntryPoint);
    pFinalPackedNtHeaders->OptionalHeader.AddressOfEntryPoint = loaderStubRva;
    logf("[INFO] New EntryPoint set to Loader Stub RVA: 0x%X.\n", loaderStubRva);

    PIMAGE_NT_HEADERS_CURRENT pVerifyNtHeaders = GetNtHeadersFromBuffer(finalPackedPEBuffer);
    if (pVerifyNtHeaders) {
        logf("[VERIFY_BUFFER] Final SizeOfHeaders: 0x%X\n", pVerifyNtHeaders->OptionalHeader.SizeOfHeaders);
        logf("[VERIFY_BUFFER] Final SizeOfImage: 0x%X\n", pVerifyNtHeaders->OptionalHeader.SizeOfImage);
        logf("[VERIFY_BUFFER] Final NumberOfSections: %u\n", pVerifyNtHeaders->FileHeader.NumberOfSections);
        logf("[VERIFY_BUFFER] Final FileAlignment: 0x%X\n", pVerifyNtHeaders->OptionalHeader.FileAlignment);
        logf("[VERIFY_BUFFER] Final SectionAlignment: 0x%X\n", pVerifyNtHeaders->OptionalHeader.SectionAlignment);

        PIMAGE_SECTION_HEADER pVerifySectionWalker = IMAGE_FIRST_SECTION(pVerifyNtHeaders);
        for (WORD i = 0; i < pVerifyNtHeaders->FileHeader.NumberOfSections; ++i) {
            logf("[VERIFY_BUFFER] Section #%u: Name='%.8s', VA=0x%X, VSize=0x%X, RawPtr=0x%X, RawSize=0x%X, Characteristics=0x%X. VA_End=0x%X, Raw_End=0x%X\n",
                i,
                (char*)pVerifySectionWalker->Name,
                pVerifySectionWalker->VirtualAddress,
                pVerifySectionWalker->Misc.VirtualSize,
                pVerifySectionWalker->PointerToRawData,
                pVerifySectionWalker->SizeOfRawData,
                pVerifySectionWalker->Characteristics,
                pVerifySectionWalker->VirtualAddress + pVerifySectionWalker->Misc.VirtualSize,
                pVerifySectionWalker->PointerToRawData + pVerifySectionWalker->SizeOfRawData
            );
            pVerifySectionWalker++;
        }
    }
    else {
        logf("[VERIFY_BUFFER] Failed to get NT headers from finalPackedPEBuffer for verification.\n");
    }

    logf("\n[INFO] Attempting to write final packed PE to: %s\n", finalPackedFile);
    FILE* fPackedOut = fopen(finalPackedFile, "wb");
    if (!fPackedOut) {
        logf("[-] Failed to open final output file: %s\n", finalPackedFile);
        free(finalPackedPEBuffer);
        if (logFile) fclose(logFile);
        return -1;
    }

    if (fwrite(finalPackedPEBuffer, 1, finalPackedPEFileSize, fPackedOut) != finalPackedPEFileSize) {
        logf("[ERROR] Failed to write all bytes of the packed PE to: %s\n", finalPackedFile);
        fclose(fPackedOut);
        free(finalPackedPEBuffer);
        if (logFile) fclose(logFile);
        return -1;
    }
    
    fclose(fPackedOut);
    logf("[SUCCESS] Final packed PE saved to: %s (%lu bytes).\n\n", finalPackedFile, finalPackedPEFileSize);

    free(finalPackedPEBuffer);
    finalPackedPEBuffer = nullptr;

    logf("[INFO] Crypting completed successfully.\n");
    if (logFile) {
        fclose(logFile);
        logFile = NULL;
    }

    return 0;
}