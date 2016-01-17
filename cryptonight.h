#ifndef __CRYPTONIGHT_H
#define __CRYPTONIGHT_H

struct cryptonight_ctx;

void cryptonight_hash_ctx(void *output, const void *input, struct cryptonight_ctx *ctx);
struct cryptonight_ctx *cryptonight_ctx();

#endif
