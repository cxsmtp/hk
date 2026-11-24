#include "HawkBoundedSHA256.h"

#include <limits.h>
#include <string.h>

static const uint32_t sRoundConstants[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t HawkRotateRight(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32U - bits));
}

static uint32_t HawkLoadBigEndian32(const uint8_t *value) {
    return ((uint32_t)value[0] << 24U) |
        ((uint32_t)value[1] << 16U) |
        ((uint32_t)value[2] << 8U) |
        (uint32_t)value[3];
}

static void HawkStoreBigEndian32(uint32_t value, uint8_t *output) {
    output[0] = (uint8_t)(value >> 24U);
    output[1] = (uint8_t)(value >> 16U);
    output[2] = (uint8_t)(value >> 8U);
    output[3] = (uint8_t)value;
}

static void HawkSHA256Transform(HawkSHA256Context *context, const uint8_t block[64]) {
    uint32_t words[64];
    for (size_t index = 0; index < 16; ++index) {
        words[index] = HawkLoadBigEndian32(&block[index * 4]);
    }
    for (size_t index = 16; index < 64; ++index) {
        const uint32_t first = HawkRotateRight(words[index - 15], 7) ^
            HawkRotateRight(words[index - 15], 18) ^
            (words[index - 15] >> 3U);
        const uint32_t second = HawkRotateRight(words[index - 2], 17) ^
            HawkRotateRight(words[index - 2], 19) ^
            (words[index - 2] >> 10U);
        words[index] = words[index - 16] + first + words[index - 7] + second;
    }

    uint32_t a = context->state[0];
    uint32_t b = context->state[1];
    uint32_t c = context->state[2];
    uint32_t d = context->state[3];
    uint32_t e = context->state[4];
    uint32_t f = context->state[5];
    uint32_t g = context->state[6];
    uint32_t h = context->state[7];

    for (size_t index = 0; index < 64; ++index) {
        const uint32_t upperSigmaOne = HawkRotateRight(e, 6) ^
            HawkRotateRight(e, 11) ^ HawkRotateRight(e, 25);
        const uint32_t choice = (e & f) ^ ((~e) & g);
        const uint32_t temporaryOne = h + upperSigmaOne + choice +
            sRoundConstants[index] + words[index];
        const uint32_t upperSigmaZero = HawkRotateRight(a, 2) ^
            HawkRotateRight(a, 13) ^ HawkRotateRight(a, 22);
        const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temporaryTwo = upperSigmaZero + majority;
        h = g;
        g = f;
        f = e;
        e = d + temporaryOne;
        d = c;
        c = b;
        b = a;
        a = temporaryOne + temporaryTwo;
    }

    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
    memset(words, 0, sizeof(words));
}

void HawkSHA256Initialize(HawkSHA256Context *context) {
    if (context == NULL) {
        return;
    }
    memset(context, 0, sizeof(*context));
    context->state[0] = 0x6a09e667U;
    context->state[1] = 0xbb67ae85U;
    context->state[2] = 0x3c6ef372U;
    context->state[3] = 0xa54ff53aU;
    context->state[4] = 0x510e527fU;
    context->state[5] = 0x9b05688cU;
    context->state[6] = 0x1f83d9abU;
    context->state[7] = 0x5be0cd19U;
}

bool HawkSHA256Update(HawkSHA256Context *context, const void *data, size_t length) {
    if (context == NULL || (length > 0 && data == NULL) ||
        length > UINT64_MAX - context->totalBytes) {
        return false;
    }
    const uint8_t *bytes = (const uint8_t *)data;
    context->totalBytes += length;
    while (length > 0) {
        if (context->bufferedBytes == 0 && length >= HAWK_SHA256_BLOCK_BYTES) {
            HawkSHA256Transform(context, bytes);
            bytes += HAWK_SHA256_BLOCK_BYTES;
            length -= HAWK_SHA256_BLOCK_BYTES;
            continue;
        }
        const size_t available = HAWK_SHA256_BLOCK_BYTES - context->bufferedBytes;
        const size_t copyLength = length < available ? length : available;
        memcpy(&context->buffer[context->bufferedBytes], bytes, copyLength);
        context->bufferedBytes += copyLength;
        bytes += copyLength;
        length -= copyLength;
        if (context->bufferedBytes == HAWK_SHA256_BLOCK_BYTES) {
            HawkSHA256Transform(context, context->buffer);
            context->bufferedBytes = 0;
        }
    }
    return true;
}

void HawkSHA256Finalize(
    HawkSHA256Context *context,
    uint8_t digest[HAWK_SHA256_DIGEST_BYTES]
) {
    if (context == NULL || digest == NULL) {
        return;
    }
    const uint64_t bitLength = context->totalBytes * 8U;
    context->buffer[context->bufferedBytes++] = 0x80U;
    if (context->bufferedBytes > 56U) {
        memset(
            &context->buffer[context->bufferedBytes],
            0,
            HAWK_SHA256_BLOCK_BYTES - context->bufferedBytes
        );
        HawkSHA256Transform(context, context->buffer);
        context->bufferedBytes = 0;
    }
    memset(&context->buffer[context->bufferedBytes], 0, 56U - context->bufferedBytes);
    for (size_t index = 0; index < 8; ++index) {
        context->buffer[63U - index] = (uint8_t)(bitLength >> (index * 8U));
    }
    HawkSHA256Transform(context, context->buffer);
    for (size_t index = 0; index < 8; ++index) {
        HawkStoreBigEndian32(context->state[index], &digest[index * 4]);
    }
    memset(context, 0, sizeof(*context));
}
