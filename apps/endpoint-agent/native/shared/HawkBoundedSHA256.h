#ifndef HAWK_BOUNDED_SHA256_H
#define HAWK_BOUNDED_SHA256_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HAWK_SHA256_DIGEST_BYTES 32U
#define HAWK_SHA256_BLOCK_BYTES 64U

typedef struct HawkSHA256Context {
    uint32_t state[8];
    uint64_t totalBytes;
    uint8_t buffer[HAWK_SHA256_BLOCK_BYTES];
    size_t bufferedBytes;
} HawkSHA256Context;

void HawkSHA256Initialize(HawkSHA256Context *context);
bool HawkSHA256Update(HawkSHA256Context *context, const void *data, size_t length);
void HawkSHA256Finalize(
    HawkSHA256Context *context,
    uint8_t digest[HAWK_SHA256_DIGEST_BYTES]
);

#endif
