#ifndef __MINERUTILS_H
#define __MINERUTILS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// ASCII <-> binary conversion routines
int ASCIIHexToBinary(void *restrict rawstr, const char *restrict asciistr, size_t len);
void BinaryToASCIIHex(char *restrict asciistr, const void *restrict rawstr, size_t len);

// Time routines

#ifdef __linux__
#define TIME_TYPE	struct timespec
#else
#define TIME_TYPE	clock_t
#endif

TIME_TYPE MinerGetCurTime(void);
double SecondsElapsed(TIME_TYPE Start, TIME_TYPE End);
#endif
