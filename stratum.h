#ifndef __STRATUM_H
#define __STRATUM_H

#include <stdint.h>
#include <stdbool.h>

typedef struct _JobInfo
{
	uint64_t XMRTarget;
	uint8_t ID[32];
	uint8_t XMRBlob[128];
	uint32_t XMRBlobLen;
	char *blockblob;
} JobInfo;

#endif
