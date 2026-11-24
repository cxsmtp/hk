#ifndef HAWK_FLOOR_DECISION_ENGINE_H
#define HAWK_FLOOR_DECISION_ENGINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HAWK_FLOOR_SCHEMA_VERSION 2U
#define HAWK_FLOOR_MAX_RULES 4096U
#define HAWK_FLOOR_MAX_PERMITS 4096U
#define HAWK_FLOOR_HASH_BYTES 32U
#define HAWK_FLOOR_REFERENCE_BYTES 64U

/* Numeric ordering is shared with EndpointPrimitive in contracts.py. */
typedef enum HawkFloorPrimitive {
    HAWK_FLOOR_FILE_OPEN = 0,
    HAWK_FLOOR_FILE_READ = 1,
    HAWK_FLOOR_FILE_WRITE = 2,
    HAWK_FLOOR_FILE_CREATE = 3,
    HAWK_FLOOR_FILE_TRUNCATE = 4,
    HAWK_FLOOR_FILE_RENAME = 5,
    HAWK_FLOOR_FILE_MOVE = 6,
    HAWK_FLOOR_FILE_DELETE = 7,
    HAWK_FLOOR_FILE_EXECUTE = 8,
    HAWK_FLOOR_FILE_MEMORY_MAP = 9,
    HAWK_FLOOR_FILE_METADATA_CHANGE = 10,
    HAWK_FLOOR_FILE_UNKNOWN = 11,
    HAWK_FLOOR_PROCESS_EXECUTE = 12,
    HAWK_FLOOR_PROCESS_CHILD_CREATE = 13,
    HAWK_FLOOR_PROCESS_SCRIPT_LAUNCH = 14,
    HAWK_FLOOR_PROCESS_INTERPRETER_LAUNCH = 15,
    HAWK_FLOOR_PROCESS_TERMINATE = 16,
    HAWK_FLOOR_PROCESS_UNKNOWN = 17,
    HAWK_FLOOR_NETWORK_CONNECT = 18,
    HAWK_FLOOR_NETWORK_ACCEPT = 19,
    HAWK_FLOOR_NETWORK_LISTEN = 20,
    HAWK_FLOOR_NETWORK_REDIRECT = 21,
    HAWK_FLOOR_NETWORK_SEND = 22,
    HAWK_FLOOR_NETWORK_RECEIVE = 23,
    HAWK_FLOOR_NETWORK_DNS = 24,
    HAWK_FLOOR_NETWORK_QUIC = 25,
    HAWK_FLOOR_NETWORK_LOCALHOST = 26,
    HAWK_FLOOR_NETWORK_UNIX_SOCKET = 27,
    HAWK_FLOOR_NETWORK_NAMED_PIPE = 28,
    HAWK_FLOOR_NETWORK_UNKNOWN = 29,
    HAWK_FLOOR_DOWNLOAD = 30,
    HAWK_FLOOR_UPLOAD = 31,
    HAWK_FLOOR_EXTERNAL_TRANSFER = 32,
    HAWK_FLOOR_INTERNAL_TRANSFER = 33,
    HAWK_FLOOR_UNKNOWN_TRANSFER = 34,
    HAWK_FLOOR_LOCAL_MCP_CONNECTION = 35,
    HAWK_FLOOR_LOCAL_AGENT_CONNECTION = 36,
    HAWK_FLOOR_LOCAL_MODEL_CONNECTION = 37,
    HAWK_FLOOR_LOCAL_SERVICE_CONNECTION = 38,
    HAWK_FLOOR_UNKNOWN_LOCAL_SERVICE = 39,
    HAWK_FLOOR_PRIMITIVE_COUNT = 40,

    /* Source compatibility only; new ABI producers use canonical names. */
    HAWK_FLOOR_PROCESS_EXEC = HAWK_FLOOR_PROCESS_EXECUTE,
    HAWK_FLOOR_LOCAL_SERVICE_ACCESS = HAWK_FLOOR_LOCAL_SERVICE_CONNECTION,
    HAWK_FLOOR_MCP_LOCAL_CONNECTION = HAWK_FLOOR_LOCAL_MCP_CONNECTION,
    HAWK_FLOOR_UNKNOWN_ENDPOINT_ACTION = HAWK_FLOOR_UNKNOWN_LOCAL_SERVICE
} HawkFloorPrimitive;

typedef enum HawkFloorAction {
    HAWK_FLOOR_ACTION_ALLOW = 0,
    HAWK_FLOOR_ACTION_BLOCK = 1,
    HAWK_FLOOR_ACTION_REQUIRE_PREAUTHORIZED_PERMIT = 2,
    HAWK_FLOOR_ACTION_REQUIRE_REMOTE_DECISION = 3,
    HAWK_FLOOR_ACTION_REQUIRE_USER_RETRY_AFTER_APPROVAL = 4,
    HAWK_FLOOR_ACTION_ALLOW_WITH_EVIDENCE = 5,

    /* Source compatibility only. */
    HAWK_FLOOR_ACTION_LOCAL_ESCALATION_REQUIRED =
        HAWK_FLOOR_ACTION_REQUIRE_USER_RETRY_AFTER_APPROVAL,
    HAWK_FLOOR_ACTION_REMOTE_ENRICHMENT_ALLOWED =
        HAWK_FLOOR_ACTION_ALLOW_WITH_EVIDENCE
} HawkFloorAction;

typedef struct HawkFloorRequest {
    uint32_t schemaVersion;
    HawkFloorPrimitive primitive;
    uint8_t tenantHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t deviceHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t processIdentityHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t processInstanceHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t binaryIdentityHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t resourceReferenceHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t stableResourceIdentityHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t destinationReferenceHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t canonicalActionHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t permitDigest[HAWK_FLOOR_HASH_BYTES];
    uint64_t requestedRights;
    uint64_t policyEpoch;
    uint32_t resourceClassification;
    uint32_t destinationClassification;
    uint32_t businessPurpose;
    uint64_t deadlineMonotonicNs;
    bool permitPresent;
} HawkFloorRequest;

typedef struct HawkFloorRule {
    uint64_t primitiveMask;
    uint32_t resourceClassificationMask;
    uint32_t destinationClassificationMask;
    uint32_t businessPurpose;
    bool bindBinaryIdentity;
    uint8_t binaryIdentityHash[HAWK_FLOOR_HASH_BYTES];
    HawkFloorAction action;
    char ruleReference[HAWK_FLOOR_REFERENCE_BYTES];
} HawkFloorRule;

typedef struct HawkFloorPermit {
    bool integrityVerified;
    HawkFloorPrimitive primitive;
    uint64_t requestedRights;
    uint64_t policyEpoch;
    uint64_t expiresAtMonotonicNs;
    uint32_t maximumUses;
    volatile uint32_t consumedUses;
    uint8_t processInstanceHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t stableResourceIdentityHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t destinationReferenceHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t canonicalActionHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t permitDigest[HAWK_FLOOR_HASH_BYTES];
} HawkFloorPermit;

typedef struct HawkFloorPolicySnapshot {
    uint32_t schemaVersion;
    bool signatureVerified;
    bool configurationIntegrityValid;
    uint8_t tenantHash[HAWK_FLOOR_HASH_BYTES];
    uint8_t deviceHash[HAWK_FLOOR_HASH_BYTES];
    uint64_t policyEpoch;
    uint64_t expiresAtMonotonicNs;
    uint32_t ruleCount;
    const HawkFloorRule *rules;
    uint32_t permitCount;
    HawkFloorPermit *permits;
    HawkFloorAction defaultActionByPrimitive[HAWK_FLOOR_PRIMITIVE_COUNT];
    char policyVersion[HAWK_FLOOR_REFERENCE_BYTES];
} HawkFloorPolicySnapshot;

typedef struct HawkFloorDecision {
    HawkFloorAction action;
    bool matchedRule;
    bool deadlineExceeded;
    bool policyAccepted;
    bool permitConsumed;
    bool permitMismatch;
    char ruleReference[HAWK_FLOOR_REFERENCE_BYTES];
    char policyVersion[HAWK_FLOOR_REFERENCE_BYTES];
} HawkFloorDecision;

HawkFloorDecision HawkFloorEvaluate(
    const HawkFloorPolicySnapshot *snapshot,
    const HawkFloorRequest *request,
    uint64_t nowMonotonicNs
);

#endif
