#include "encrypter.hpp"
#include "main.hpp"
#include <stdio.h>
#include <windows.h>

bool encrypter_main(const char* inputFile, const char* outputFile, BYTE key, BYTE** outBuffer, DWORD* outSize) {
	logf("-- Encrypting %s to %s with key 0x%02X\n", inputFile, outputFile, key);
    
    HANDLE hFile = CreateFileA(inputFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        logf("[-] Failed to open input file: %s\n", inputFile);
        return false;
    } else
		logf("[+] Opened %s with handle: 0x%p\n", inputFile, hFile);

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize);

    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        logf("Failed to read input file.\n");
        CloseHandle(hFile);
        HeapFree(GetProcessHeap(), 0, buffer);
        return false;
    }
    
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		logf("[-] Not a valid PE file.\n");
		HeapFree(GetProcessHeap(), 0, buffer);
		return false;
	}

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		logf("[-] Not a valid PE file.\n");
		HeapFree(GetProcessHeap(), 0, buffer);
		return false;
	}

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    
    bool found = false;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        const char* secName = (char*)section->Name;

        if (strcmp(secName, ".text") == 0 || strcmp(secName, ".data") == 0 || strcmp(secName, ".rdata") == 0) {
            DWORD rawOffset = section->PointerToRawData;
            DWORD size = section->SizeOfRawData;

            for (DWORD j = 0; j < size; j++) {
                buffer[rawOffset + j] ^= key;
            }

            logf("[+] Encrypted section: %s\n", secName);
            found = true;
        }
    }

    if (!found)
        logf("Bro, none of the target sections (.text, .data, .rdata) were found (You're cooked)\n");

    HANDLE hOutFile = CreateFileA(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutFile == INVALID_HANDLE_VALUE) {
        logf("[-] Failed to open output file: %s\n", outputFile);
        HeapFree(GetProcessHeap(), 0, buffer);
        return false;
    }

    DWORD bytesWritten;
    if (!WriteFile(hOutFile, buffer, fileSize, &bytesWritten, NULL)) {
        logf("[-] Failed to write encrypted data to file.\n");
        CloseHandle(hOutFile);
        HeapFree(GetProcessHeap(), 0, buffer);
        return false;
    }

    if (bytesWritten != fileSize) {
        logf("[-] Write size mismatch (wrote %lu of %lu)\n", bytesWritten, fileSize);
        CloseHandle(hOutFile);
        HeapFree(GetProcessHeap(), 0, buffer);
        return false;
    }

    *outBuffer = buffer;
    *outSize = fileSize;

    CloseHandle(hOutFile);

    logf("[+] Successfully encrypted %s to %s using key 0x%02X\n", inputFile, outputFile, key);
    return true;
}
