#ifndef HAWK_MAC_CODE_IDENTITY_H
#define HAWK_MAC_CODE_IDENTITY_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <EndpointSecurity/EndpointSecurity.h>

#include "../../shared/HawkFloorDecisionEngine.h"

bool HawkMacCodeIdentityFromESProcess(
    const es_process_t *process,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
);

bool HawkMacCodeIdentityFromComponents(
    const uint8_t *team, size_t teamLength,
    const uint8_t *signing, size_t signingLength,
    const uint8_t cdhash[20], bool platformBinary,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
);

bool HawkMacCodeIdentityFromAuditToken(
    const uint8_t *auditToken, size_t auditTokenLength,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
);

#endif
