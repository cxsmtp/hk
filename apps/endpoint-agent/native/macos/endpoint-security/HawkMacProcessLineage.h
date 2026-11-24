#ifndef HAWK_MAC_PROCESS_LINEAGE_H
#define HAWK_MAC_PROCESS_LINEAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <bsm/libbsm.h>

#include <EndpointSecurity/EndpointSecurity.h>
#include "../../shared/HawkFloorDecisionEngine.h"

#define HAWK_MAC_PROCESS_LINEAGE_CAPACITY 512U

typedef struct HawkMacProcessLineageHealth {
    uint32_t occupancy;
    uint64_t recordFailureCount;
} HawkMacProcessLineageHealth;

void HawkMacProcessLineageClear(void);
bool HawkMacProcessLineageCopyHealth(HawkMacProcessLineageHealth *health);
void HawkMacProcessLineageRemove(audit_token_t processToken);
bool HawkMacProcessLineageLookup(
    audit_token_t processToken,
    uint8_t rootIdentity[HAWK_FLOOR_HASH_BYTES]
);
bool HawkMacProcessLineageRecordExec(
    audit_token_t parentToken,
    audit_token_t targetToken,
    const uint8_t inheritedRoot[HAWK_FLOOR_HASH_BYTES],
    const uint8_t targetIdentity[HAWK_FLOOR_HASH_BYTES],
    bool targetIsGoverned,
    bool operationAllowed
);

#endif
