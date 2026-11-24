#ifndef HAWK_SHA256_H
#define HAWK_SHA256_H

#include <ntddk.h>

VOID HawkSha256Bytes(
    _In_reads_bytes_(Length) const UCHAR *Bytes,
    _In_ SIZE_T Length,
    _Out_writes_(32) UCHAR Digest[32]
);

VOID HawkSha256UnicodeInsensitive(
    _In_opt_ PCUNICODE_STRING Value,
    _Out_writes_(32) UCHAR Digest[32]
);

#endif
