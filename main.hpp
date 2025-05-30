#pragma once

#include <windows.h>

//--------------------------------

#define yapBad(fmt, ...)  printf("[*_*]  (%s:%d) - " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define yapGood(fmt, ...) printf("[^-^]  (%s:%d) - " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define yapYap(fmt, ...)  printf("[-_-]  (%s:%d) - " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

//--------------------------------

void logf(const char* fmt, ...);