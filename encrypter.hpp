#pragma once

#include "main.hpp"

typedef unsigned char BYTE;
typedef unsigned long DWORD;

bool encrypter_main(const char* inputFile, const char* outputFile, BYTE key, BYTE** outBuffer, DWORD *outSize);