#include "common.hpp"
#include "main.hpp"

extern PIMAGE_NT_HEADERS_CURRENT GetNtHeadersFromBuffer(BYTE* pBuffer) {
    if (!pBuffer) return NULL;
    
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        logf("[-] Invalid DOS signature.\n");
        return NULL;
    }
    
    if (pDosHeader->e_lfanew > 1024 || pDosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER)) {
        logf("[-] GetNtHeadersFromBuffer: Suspicious e_lfanew value (0x%X).\n", pDosHeader->e_lfanew);
        return NULL;
    }

    PIMAGE_NT_HEADERS_CURRENT pNtHeaders = (PIMAGE_NT_HEADERS_CURRENT)(pBuffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        logf("[-] Invalid NT signature.\n");
        return NULL;
    }

    #if defined(_WIN64)
        if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            logf("[-] GetNtHeadersFromBuffer: Not a 64-bit PE (Magic: 0x%X).\n", pNtHeaders->OptionalHeader.Magic);
            return NULL;
        }
    #else // 32-bit
        if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            logf("[-] GetNtHeadersFromBuffer: Not a 32-bit PE (Magic: 0x%X).\n", pNtHeaders->OptionalHeader.Magic);
            return NULL;
        }
    #endif

    return pNtHeaders;
}

extern DWORD RvaToRawOffset(PIMAGE_NT_HEADERS_CURRENT pNtHeaders, DWORD dwRva, BYTE* pImageBase) {
    if (!pNtHeaders || !pImageBase) return 0;

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        if (dwRva >= pSectionHeader->VirtualAddress &&
            dwRva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize) {
            return (dwRva - pSectionHeader->VirtualAddress) + pSectionHeader->PointerToRawData;
        }
    }
    
    if (dwRva < pNtHeaders->OptionalHeader.SizeOfHeaders && dwRva < pSectionHeader->VirtualAddress) {
        return dwRva;
    }
    logf("[-] RvaToRawOffset: RVA 0x%X not found in any section.\n", dwRva);
    return 0;
}