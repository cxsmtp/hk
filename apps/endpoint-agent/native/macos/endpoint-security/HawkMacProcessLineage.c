#include "HawkMacProcessLineage.h"

#include <os/lock.h>
#include <string.h>

typedef struct HawkMacLineageRow {
    audit_token_t token;
    int32_t pidVersion;
    uint8_t rootIdentity[HAWK_FLOOR_HASH_BYTES];
    bool occupied;
} HawkMacLineageRow;

static os_unfair_lock sLineageLock = OS_UNFAIR_LOCK_INIT;
static HawkMacLineageRow sRows[HAWK_MAC_PROCESS_LINEAGE_CAPACITY];
static uint64_t sRecordFailureCount;

static bool HawkTokenEqual(audit_token_t left, audit_token_t right) {
    return memcmp(&left, &right, sizeof(left)) == 0;
}

static uint32_t HawkLineageIndex(audit_token_t token) {
    uint32_t value = (uint32_t)audit_token_to_pid(token) ^
        (uint32_t)audit_token_to_pidversion(token);
    return value % HAWK_MAC_PROCESS_LINEAGE_CAPACITY;
}

void HawkMacProcessLineageClear(void) {
    os_unfair_lock_lock(&sLineageLock);
    memset(sRows, 0, sizeof(sRows));
    sRecordFailureCount = 0;
    os_unfair_lock_unlock(&sLineageLock);
}

bool HawkMacProcessLineageCopyHealth(HawkMacProcessLineageHealth *health) {
    if (health == NULL) return false;
    os_unfair_lock_lock(&sLineageLock);
    uint32_t occupancy = 0;
    for (uint32_t index = 0; index < HAWK_MAC_PROCESS_LINEAGE_CAPACITY; ++index)
        if (sRows[index].occupied) ++occupancy;
    health->occupancy = occupancy;
    health->recordFailureCount = sRecordFailureCount;
    os_unfair_lock_unlock(&sLineageLock);
    return true;
}

bool HawkMacProcessLineageLookup(audit_token_t processToken, uint8_t rootIdentity[HAWK_FLOOR_HASH_BYTES]) {
    if (rootIdentity == NULL) return false;
    os_unfair_lock_lock(&sLineageLock);
    const uint32_t start = HawkLineageIndex(processToken);
    for (uint32_t offset = 0; offset < HAWK_MAC_PROCESS_LINEAGE_CAPACITY; ++offset) {
        HawkMacLineageRow *row = &sRows[(start + offset) % HAWK_MAC_PROCESS_LINEAGE_CAPACITY];
        if (row->pidVersion == audit_token_to_pidversion(processToken) &&
            row->occupied && HawkTokenEqual(row->token, processToken)) {
            memcpy(rootIdentity, row->rootIdentity, HAWK_FLOOR_HASH_BYTES);
            os_unfair_lock_unlock(&sLineageLock);
            return true;
        }
    }
    os_unfair_lock_unlock(&sLineageLock);
    return false;
}

void HawkMacProcessLineageRemove(audit_token_t processToken) {
    os_unfair_lock_lock(&sLineageLock);
    for (uint32_t index = 0; index < HAWK_MAC_PROCESS_LINEAGE_CAPACITY; ++index) {
        HawkMacLineageRow *row = &sRows[index];
        if (row->occupied && row->pidVersion == audit_token_to_pidversion(processToken) &&
            HawkTokenEqual(row->token, processToken)) {
            memset(row, 0, sizeof(*row));
            break;
        }
    }
    os_unfair_lock_unlock(&sLineageLock);
}

bool HawkMacProcessLineageRecordExec(
    audit_token_t parentToken,
    audit_token_t targetToken,
    const uint8_t inheritedRoot[HAWK_FLOOR_HASH_BYTES],
    const uint8_t targetIdentity[HAWK_FLOOR_HASH_BYTES],
    bool targetIsGoverned,
    bool operationAllowed
) {
    if (!operationAllowed || inheritedRoot == NULL || targetIdentity == NULL) return false;
    const uint8_t *root = targetIsGoverned ? targetIdentity : inheritedRoot;
    uint8_t nonzero = 0;
    for (size_t index = 0; index < HAWK_FLOOR_HASH_BYTES; ++index) nonzero |= root[index];
    if (nonzero == 0) return false;
    os_unfair_lock_lock(&sLineageLock);
    const uint32_t start = HawkLineageIndex(targetToken);
    HawkMacLineageRow *destination = NULL;
    for (uint32_t offset = 0; offset < HAWK_MAC_PROCESS_LINEAGE_CAPACITY; ++offset) {
        HawkMacLineageRow *row = &sRows[(start + offset) % HAWK_MAC_PROCESS_LINEAGE_CAPACITY];
        if (!row->occupied || (row->pidVersion == audit_token_to_pidversion(targetToken) &&
            HawkTokenEqual(row->token, targetToken))) {
            destination = row;
            break;
        }
    }
    if (destination == NULL) {
        if (sRecordFailureCount != UINT64_MAX) ++sRecordFailureCount;
        os_unfair_lock_unlock(&sLineageLock);
        return false;
    }
    destination->token = targetToken;
    destination->pidVersion = audit_token_to_pidversion(targetToken);
    memcpy(destination->rootIdentity, root, HAWK_FLOOR_HASH_BYTES);
    destination->occupied = true;
    (void)parentToken;
    os_unfair_lock_unlock(&sLineageLock);
    return true;
}
