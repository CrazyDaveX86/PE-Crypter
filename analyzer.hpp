#pragma once

#include "main.hpp"

DWORD RvaToRaw(LPBYTE base, DWORD rva, PIMAGE_NT_HEADERS nt);
void PrintSectionInfo(PIMAGE_SECTION_HEADER section, int index);
void PrintImports(LPBYTE base, DWORD importRVA, PIMAGE_NT_HEADERS ntHeaders);
BOOL analyzer_main(const char* inputfile);