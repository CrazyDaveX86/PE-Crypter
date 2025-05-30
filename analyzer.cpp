#include "main.hpp"
#include <Windows.h>
#include "analyzer.hpp"

DWORD RvaToRaw(LPBYTE base, DWORD rva, PIMAGE_NT_HEADERS nt) {
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        DWORD va = sec->VirtualAddress;
        DWORD size = sec->SizeOfRawData;

        if (rva >= va && rva < va + sec->Misc.VirtualSize) {
            return sec->PointerToRawData + (rva - va);
        }
    }
    return 0;
}

void PrintSectionInfo(PIMAGE_SECTION_HEADER section, int index) {
    logf("[SECTION #%d] %s\n", index + 1, section->Name);
    logf("  VirtualSize     : 0x%08X\n", section->Misc.VirtualSize);
    logf("  VirtualAddress  : 0x%08X\n", section->VirtualAddress);
    logf("  SizeOfRawData   : 0x%08X\n", section->SizeOfRawData);
    logf("  PointerToRawData: 0x%08X\n", section->PointerToRawData);
    logf("  Characteristics : 0x%08X\n", section->Characteristics);
    logf("\n");
}

void PrintImports(LPBYTE base, DWORD importRVA, PIMAGE_NT_HEADERS ntHeaders) {
    DWORD importOffset = RvaToRaw(base, importRVA, ntHeaders);
    if (!importOffset) {
        logf("Import table not found!\n");
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(base + importOffset);
    logf("[IMPORT TABLE]\n");

    while (importDesc->Name) {
        DWORD nameOffset = RvaToRaw(base, importDesc->Name, ntHeaders);
        const char* dllName = (const char*)(base + nameOffset);
        logf("  DLL: %s\n", dllName);

        DWORD thunkRVA = importDesc->OriginalFirstThunk ?
            importDesc->OriginalFirstThunk :
            importDesc->FirstThunk;
        DWORD thunkOffset = RvaToRaw(base, thunkRVA, ntHeaders);

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(base + thunkOffset);
        while (thunk->u1.AddressOfData) {
            if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                DWORD impOffset = RvaToRaw(base, thunk->u1.AddressOfData, ntHeaders);
                PIMAGE_IMPORT_BY_NAME impByName = (PIMAGE_IMPORT_BY_NAME)(base + impOffset);
                logf("    > %s\n", impByName->Name);
            }
            else {
                logf("    > Ordinal: %u\n", IMAGE_ORDINAL(thunk->u1.Ordinal));
            }
            thunk++;
        }

        logf("\n");
        importDesc++;
    }
}

BOOL analyzer_main(const char* inputfile) {
    logf("-- For: %s\n\n", inputfile);
    
    HANDLE hFile = CreateFileA(inputfile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        logf("Failed to open %s lol\n", inputfile);
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize);

    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        DWORD bytesRead;  
        if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {  
           logf("Unable to read file: %s\n", inputfile);  
           CloseHandle(hFile);  
           HeapFree(GetProcessHeap(), 0, buffer);  
           return FALSE;  
        } else if (bytesRead != fileSize) {  
           logf("Incomplete read: expected %lu bytes, but read %lu bytes\n", fileSize, bytesRead);  
           CloseHandle(hFile);  
           HeapFree(GetProcessHeap(), 0, buffer);  
           return FALSE;  
        }
		logf("Unable to read file: %s\n", inputfile);
		CloseHandle(hFile);
		HeapFree(GetProcessHeap(), 0, buffer);
		return FALSE;
    }
    CloseHandle(hFile);

    if (!buffer) {
        logf("Buffer allocation failed!");
        return FALSE;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        logf("Not a valid PE fam");
		CloseHandle(hFile);
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        logf("Not a valid PE fam");
        HeapFree(GetProcessHeap(), 0, buffer);
		CloseHandle(hFile);
        return FALSE;
    }

    WORD arch = ntHeaders->FileHeader.Machine;
    logf("Architecture    : %s\n", (arch == IMAGE_FILE_MACHINE_I386) ? "x86" : "x64");
    logf("Entrypoint      : 0x%08X\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);
    logf("ImageBase       : 0x%08X\n", ntHeaders->OptionalHeader.ImageBase);
    logf("Sections        : %d\n", ntHeaders->FileHeader.NumberOfSections);
    logf("Import RVA      : 0x%08X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    logf("OEP RVA         : 0x%08X (saved)\n\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);
    logf("Alignment       : 0x%08X (saved)\n\n", ntHeaders->OptionalHeader.SectionAlignment);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PrintSectionInfo(&section[i], i);
    }
    logf("\n");


    DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD rawImportOffset = RvaToRaw(buffer, importRVA, ntHeaders);
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(buffer + rawImportOffset);
    if (importRVA) 
        PrintImports(buffer, importRVA, ntHeaders);
    else
        logf("DAYUMNNN!! No import table found\n");
    

    HeapFree(GetProcessHeap(), 0, buffer);
    return TRUE;
}