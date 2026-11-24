#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <os/log.h>
#include <string.h>

#include "../../shared/HawkFloorDecisionEngine.h"
#include "../shared/HawkMacPolicyBridge.h"
#include "HawkMacEndpointRequest.h"
#include "HawkMacProcessLineage.h"

static es_client_t *sClient = NULL;

static uint64_t HawkMonotonicNanoseconds(void) {
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    const __uint128_t scaled = (__uint128_t)mach_absolute_time() * timebase.numer;
    return (uint64_t)(scaled / timebase.denom);
}

static HawkFloorPrimitive HawkPrimitiveForMessage(const es_message_t *message) {
    switch (message->event_type) {
        case ES_EVENT_TYPE_AUTH_EXEC:
            return HAWK_FLOOR_PROCESS_EXEC;
        case ES_EVENT_TYPE_AUTH_OPEN:
            if ((message->event.open.fflag & FWRITE) != 0) {
                return HAWK_FLOOR_FILE_WRITE;
            }
            if ((message->event.open.fflag & FREAD) != 0) {
                return HAWK_FLOOR_FILE_READ;
            }
            return HAWK_FLOOR_FILE_OPEN;
        case ES_EVENT_TYPE_AUTH_CREATE:
            return HAWK_FLOOR_FILE_CREATE;
        case ES_EVENT_TYPE_AUTH_RENAME:
            return HAWK_FLOOR_FILE_RENAME;
        case ES_EVENT_TYPE_AUTH_UNLINK:
            return HAWK_FLOOR_FILE_DELETE;
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            return HAWK_FLOOR_FILE_TRUNCATE;
        case ES_EVENT_TYPE_AUTH_MMAP:
            return HAWK_FLOOR_FILE_MEMORY_MAP;
        case ES_EVENT_TYPE_AUTH_LINK:
        case ES_EVENT_TYPE_AUTH_CLONE:
        case ES_EVENT_TYPE_AUTH_COPYFILE:
            return HAWK_FLOOR_FILE_CREATE;
        case ES_EVENT_TYPE_AUTH_SETEXTATTR:
        case ES_EVENT_TYPE_AUTH_SETFLAGS:
        case ES_EVENT_TYPE_AUTH_SETMODE:
        case ES_EVENT_TYPE_AUTH_SETOWNER:
            return HAWK_FLOOR_FILE_METADATA_CHANGE;
        default:
            return HAWK_FLOOR_UNKNOWN_ENDPOINT_ACTION;
    }
}

static void HawkPolicyEpochChanged(
    uint64_t previousPolicyEpoch,
    uint64_t currentPolicyEpoch,
    void *context
) {
    (void)previousPolicyEpoch;
    (void)currentPolicyEpoch;
    (void)context;
    HawkMacProcessLineageClear();
    if (sClient == NULL) {
        return;
    }
    const es_clear_cache_result_t result = es_clear_cache(sClient);
    if (result != ES_CLEAR_CACHE_RESULT_SUCCESS) {
        os_log_error(OS_LOG_DEFAULT, "Hawk could not clear Endpoint Security cache");
    }
}

static void HawkRespond(es_client_t *client, const es_message_t *message) {
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXIT) {
        HawkMacProcessLineageRemove(message->process->audit_token);
        return;
    }
    HawkFloorRequest request;
    memset(&request, 0, sizeof(request));
    const HawkFloorPrimitive primitive = HawkPrimitiveForMessage(message);
    const bool built = HawkBuildRequestFromESMessage(message, primitive, &request);
    HawkFloorDecision decision;
    if (built) {
        decision = HawkEvaluateCurrentFloorRequest(
            &request,
            HawkMonotonicNanoseconds()
        );
    } else {
        memset(&decision, 0, sizeof(decision));
        uint8_t actorIdentity[HAWK_FLOOR_HASH_BYTES];
        const bool resolved = HawkMacProcessLineageLookup(message->process->audit_token,
                actorIdentity) || HawkBuildStableCodeIdentity(message->process,
                actorIdentity);
        decision.action = resolved && HawkMacIsBinaryIdentityGoverned(actorIdentity) &&
                HawkMacCurrentEnforcementMode() == HAWK_MAC_ENFORCEMENT_ENFORCE
            ? HAWK_FLOOR_ACTION_BLOCK : HAWK_FLOOR_ACTION_ALLOW;
        memset(actorIdentity, 0, sizeof(actorIdentity));
        decision.policyAccepted = false;
    }
    bool allow = decision.action == HAWK_FLOOR_ACTION_ALLOW ||
        decision.action == HAWK_FLOOR_ACTION_ALLOW_WITH_EVIDENCE;
    bool recordedExec = false;
    if (built && message->event_type == ES_EVENT_TYPE_AUTH_EXEC && allow) {
        uint8_t targetIdentity[HAWK_FLOOR_HASH_BYTES];
        if (HawkBuildStableCodeIdentity(message->event.exec.target, targetIdentity)) {
            const bool governedRoot = HawkMacIsBinaryIdentityGoverned(request.binaryIdentityHash);
            if (governedRoot) {
                recordedExec = HawkMacProcessLineageRecordExec(
                    message->process->audit_token,
                    message->event.exec.target->audit_token,
                    request.binaryIdentityHash,
                    targetIdentity,
                    HawkMacIsBinaryIdentityGoverned(targetIdentity), true);
                if (!recordedExec && HawkMacCurrentEnforcementMode() ==
                        HAWK_MAC_ENFORCEMENT_ENFORCE) allow = false;
            }
        } else if (HawkMacIsBinaryIdentityGoverned(request.binaryIdentityHash) &&
                   HawkMacCurrentEnforcementMode() == HAWK_MAC_ENFORCEMENT_ENFORCE) {
            allow = false;
        }
        memset(targetIdentity, 0, sizeof(targetIdentity));
    }
    es_respond_result_t response;
    if (message->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
        const uint32_t flags = allow ? message->event.open.fflag : 0;
        response = es_respond_flags_result(client, message, flags, false);
    } else {
        response = es_respond_auth_result(
            client,
            message,
            allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY,
            false
        );
    }
    if (recordedExec && response != ES_RESPOND_RESULT_SUCCESS) {
        HawkMacProcessLineageRemove(message->event.exec.target->audit_token);
    }
}

int HawkStartEndpointSecurityClient(void) {
    const es_new_client_result_t result = es_new_client(&sClient, ^(es_client_t *client, const es_message_t *message) {
        HawkRespond(client, message);
    });
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS || sClient == NULL) {
        return (int)result;
    }
    HawkMacProcessLineageClear();
    HawkMacSetPolicyEpochObserver(HawkPolicyEpochChanged, NULL);
    (void)es_clear_cache(sClient);
    const es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_AUTH_CREATE,
        ES_EVENT_TYPE_AUTH_RENAME,
        ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_AUTH_TRUNCATE,
        ES_EVENT_TYPE_AUTH_MMAP,
        ES_EVENT_TYPE_AUTH_LINK,
        ES_EVENT_TYPE_AUTH_SETEXTATTR,
        ES_EVENT_TYPE_AUTH_SETFLAGS,
        ES_EVENT_TYPE_AUTH_SETMODE,
        ES_EVENT_TYPE_AUTH_SETOWNER,
        ES_EVENT_TYPE_AUTH_CLONE,
        ES_EVENT_TYPE_AUTH_COPYFILE,
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_NOTIFY_EXIT,
    };
    const es_return_t subscribed = es_subscribe(
        sClient,
        events,
        sizeof(events) / sizeof(events[0])
    );
    if (subscribed != ES_RETURN_SUCCESS) {
        HawkMacSetPolicyEpochObserver(NULL, NULL);
        es_delete_client(sClient);
        sClient = NULL;
        return (int)subscribed;
    }
    return 0;
}

void HawkStopEndpointSecurityClient(void) {
    if (sClient == NULL) {
        return;
    }
    HawkMacSetPolicyEpochObserver(NULL, NULL);
    es_unsubscribe_all(sClient);
    es_delete_client(sClient);
    sClient = NULL;
    HawkMacProcessLineageClear();
}
