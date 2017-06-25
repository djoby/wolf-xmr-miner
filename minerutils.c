#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "minerutils.h"

// Parameter len is bytes in rawstr, therefore, asciistr must have
// at least (len << 1) + 1 bytes allocated, the last for the NULL
void BinaryToASCIIHex(char *restrict asciistr, const void *restrict rawstr, size_t len)
{
	for(int i = 0, j = 0; i < len; ++i)
	{
		asciistr[j++] = "0123456789abcdef"[((uint8_t *)rawstr)[i] >> 4];
		asciistr[j++] = "0123456789abcdef"[((uint8_t *)rawstr)[i] & 0x0F];
	}
		
	asciistr[len << 1] = 0x00;
}

// Parameter len is the size in bytes of asciistr, meaning rawstr
// must have (len >> 1) bytes allocated
// Maybe asciistr just NULL terminated?
// Returns length of rawstr in bytes
int ASCIIHexToBinary(void *restrict rawstr, const char *restrict asciistr, size_t len)
{
	for(int i = 0, j = 0; i < len; ++i)
	{
		char tmp = asciistr[i];
		if(tmp < 'A') tmp -= '0';
		else if(tmp < 'a') tmp = (tmp - 'A') + 10;
		else tmp = (tmp - 'a') + 10;
		
		if(i & 1) ((uint8_t *)rawstr)[j++] |= tmp & 0x0F;
		else ((uint8_t *)rawstr)[j] = tmp << 4;
	}
	
	return(len >> 1);
}

#ifdef __linux__

TIME_TYPE MinerGetCurTime(void)
{
	TIME_TYPE CurTime;
	clock_gettime(CLOCK_REALTIME, &CurTime);
	return(CurTime);
}

double SecondsElapsed(TIME_TYPE Start, TIME_TYPE End)
{
	double NanosecondsElapsed = 1e9 * (double)(End.tv_sec - Start.tv_sec) + (double)(End.tv_nsec - Start.tv_nsec);
	return(NanosecondsElapsed * 1e-9);
}

#else

TIME_TYPE MinerGetCurTime(void)
{
	return(clock());
}

double SecondsElapsed(TIME_TYPE Start, TIME_TYPE End)
{
	return((double)(End - Start) / CLOCKS_PER_SEC);
}

#endif

