#pragma once

#ifndef COMMON_H
#define COMMON_H

#include "main.hpp"

//-------------------------------

#ifndef _WIN64
	typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS_CURRENT;
	typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS_CURRENT;
#else
	typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS_CURRENT;
	typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS_CURRENT;
#endif

//--------------------------------- 

extern PIMAGE_NT_HEADERS_CURRENT GetNtHeadersFromBuffer(BYTE* pBuffer);
extern DWORD RvaToRawOffset(PIMAGE_NT_HEADERS_CURRENT pNtHeaders, DWORD dwRva, BYTE* pImageBase);

#endif