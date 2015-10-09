#ifndef __MINERUTILS_H
#define __MINERUTILS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// Endian swapping routines
uint32_t BSWAP32(uint32_t data);
void SwapBuffer32(void *data, int chunks);

// ASCII <-> binary conversion routines
int ASCIIHexToBinary(void *restrict rawstr, const char *restrict asciistr, size_t len);
void BinaryToASCIIHex(char *restrict asciistr, const void *restrict rawstr, size_t len);

// File reading routine
size_t LoadTextFile(char **Output, char *Filename);

// Difficulty conversion & validity testing routines
void CreateTargetFromDiff(uint32_t *FullTarget, double Diff);
bool FullTest(const uint32_t *Hash, const uint32_t *FullTarget);

#endif
