#ifndef HAWK_KERNEL_POLICY_IOCTL_H
#define HAWK_KERNEL_POLICY_IOCTL_H

#include <stdint.h>

#include "../../shared/HawkFloorDecisionEngine.h"

#define HAWK_WINDOWS_POLICY_MAGIC 0x4B574148U /* HAWK */
#define HAWK_WINDOWS_POLICY_VERSION 4U
#define HAWK_WINDOWS_MAX_POLICY_BYTES (1024U * 1024U)
#define HAWK_WINDOWS_MAX_PROCESS_SEED_COUNT 16384U
#define HAWK_WINDOWS_PROCESS_SEED_VERSION 1U
#define HAWK_WINDOWS_DEVICE_TYPE 0x8337U

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#define METHOD_BUFFERED 0U
#define FILE_READ_DATA 0x0001U
#define FILE_WRITE_DATA 0x0002U
#endif

#define IOCTL_HAWK_POLICY_REPLACE \
    CTL_CODE(HAWK_WINDOWS_DEVICE_TYPE, 0x801U, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_HAWK_POLICY_ARM \
    CTL_CODE(HAWK_WINDOWS_DEVICE_TYPE, 0x802U, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_HAWK_POLICY_STATUS \
    CTL_CODE(HAWK_WINDOWS_DEVICE_TYPE, 0x803U, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_HAWK_PROCESS_SEED \
    CTL_CODE(HAWK_WINDOWS_DEVICE_TYPE, 0x804U, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_HAWK_PERMITS_REPLACE \
    CTL_CODE(HAWK_WINDOWS_DEVICE_TYPE, 0x805U, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_HAWK_PROCESS_IDENTITY_QUERY \
    CTL_CODE(HAWK_WINDOWS_DEVICE_TYPE, 0x806U, METHOD_BUFFERED, \
        FILE_READ_DATA | FILE_WRITE_DATA)

#define HAWK_WINDOWS_PERMIT_MAGIC 0x54504B48U /* HKPT */
#define HAWK_WINDOWS_PERMIT_VERSION 2U
#define HAWK_WINDOWS_MAX_PERMIT_BYTES HAWK_WINDOWS_MAX_POLICY_BYTES

#pragma pack(push, 1)
typedef struct HawkWindowsPolicyEnvelope {
    uint32_t magic;
    uint32_t version;
    uint32_t totalSize;
    uint32_t ruleCount;
    uint64_t generation;
    uint64_t policySequence;
    /* Relative duration; the kernel converts it using KeQueryInterruptTime. */
    uint64_t validForNanoseconds;
    uint8_t policyFingerprint[HAWK_FLOOR_HASH_BYTES];
    uint8_t tenantHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t deviceHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t signatureVerified;
    uint8_t configurationIntegrityValid;
    uint8_t reserved[6];
    char policyVersion[HAWK_FLOOR_REFERENCE_BYTES];
    HawkFloorAction defaultActionByPrimitive[HAWK_FLOOR_PRIMITIVE_COUNT];
    HawkFloorRule rules[1];
} HawkWindowsPolicyEnvelope;

typedef struct HawkWindowsArmRequest {
    uint32_t version;
    uint8_t armed;
    uint8_t reserved[3];
    uint64_t expectedGeneration;
} HawkWindowsArmRequest;

typedef struct HawkWindowsPolicyStatus {
    uint32_t version;
    uint8_t armed;
    uint8_t policyLoaded;
    uint8_t policyCurrent;
    uint8_t identityCoverageReady;
    uint8_t wfpReady;
    uint8_t reserved[3];
    uint64_t generation;
    uint64_t policySequence;
    uint64_t permitBatchSequence;
    uint64_t armSessionEpoch;
    uint64_t allowCount;
    uint64_t blockCount;
    uint64_t policyRejectCount;
    uint8_t policyFingerprint[HAWK_FLOOR_HASH_BYTES];
    uint8_t driverSessionId[16];
} HawkWindowsPolicyStatus;

typedef struct HawkWindowsProcessSeedEntry {
    uint64_t processId;
    uint64_t parentProcessId;
} HawkWindowsProcessSeedEntry;

typedef struct HawkWindowsProcessSeedRequest {
    uint32_t version;
    uint32_t processCount;
    HawkWindowsProcessSeedEntry processes[1];
} HawkWindowsProcessSeedRequest;

typedef struct HawkWindowsPermitEntry {
    uint8_t integrityVerified;
    uint8_t reserved0[3];
    uint32_t primitive;
    uint64_t requestedRights;
    uint64_t validForNanoseconds;
    uint32_t maximumUses;
    uint8_t reserved1[4];
    uint8_t processInstanceHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t stableResourceIdentityHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t destinationReferenceHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t canonicalActionHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t permitDigest[HAWK_FLOOR_HASH_BYTES];
} HawkWindowsPermitEntry;

typedef struct HawkWindowsPermitEnvelope {
    uint32_t magic;
    uint32_t version;
    uint32_t totalSize;
    uint32_t permitCount;
    uint64_t policyGeneration;
    uint64_t policySequence;
    uint64_t permitBatchSequence;
    uint64_t armSessionEpoch;
    uint8_t policyFingerprint[HAWK_FLOOR_HASH_BYTES];
    uint8_t tenantHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t deviceHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t driverSessionId[16];
    uint8_t brokerAuthenticated;
    uint8_t configurationIntegrityValid;
    uint8_t reserved[6];
    HawkWindowsPermitEntry permits[1];
} HawkWindowsPermitEnvelope;

typedef struct HawkWindowsProcessIdentityQuery {
    uint32_t version;
    uint32_t reserved;
    uint64_t processId;
} HawkWindowsProcessIdentityQuery;

typedef struct HawkWindowsProcessIdentityResponse {
    uint32_t version;
    uint32_t reserved;
    uint64_t processId;
    uint8_t binaryIdentityHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t policyBinaryIdentityHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t processInstanceHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t familyRootInstanceHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t governedLineage;
    uint8_t reserved1[7];
} HawkWindowsProcessIdentityResponse;
#pragma pack(pop)

#endif
