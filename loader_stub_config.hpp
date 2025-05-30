#pragma once  

#ifndef LOADER_STUB_CONFIG_H  
#define LOADER_STUB_CONFIG_H  

#include "main.hpp"

#pragma pack(push, 1)  
typedef struct {
	DWORD originalOepRva;   // Offset 0  
	BYTE  decryptionKey;    // Offset 4  
	DWORD hookMarker;       // Offset 5  
	DWORD textSectionRva;   // Offset 9  
	DWORD textSectionVirtualSize;   // Offset 13  
	DWORD rdataSectionRva;  // Offset 17  
	DWORD rdataSectionVirtualSize;  // Offset 21  
	DWORD dataSectionRva;        // Offset 25  
	DWORD dataSectionVirtualSize; // Offset 29
} LoaderMetadata;
#pragma pack(pop)

extern unsigned char g_loaderStubShellcode[];
extern DWORD g_loaderStubShellcodeSize;

#endif