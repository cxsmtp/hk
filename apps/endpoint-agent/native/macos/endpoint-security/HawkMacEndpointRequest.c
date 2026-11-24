#include "HawkMacEndpointRequest.h"

#include <bsm/libbsm.h>
#include <mach/mach_time.h>
#include <string.h>

#include "../../shared/HawkBoundedSHA256.h"
#include "../shared/HawkMacPolicyBridge.h"
#include "../shared/HawkMacCodeIdentity.h"
#include "HawkMacProcessLineage.h"

#define HAWK_MAC_MAX_ES_TOKEN_BYTES 16384U

static bool HawkHashToken(HawkSHA256Context *context, es_string_token_t token) {
    if (token.length > HAWK_MAC_MAX_ES_TOKEN_BYTES ||
        (token.length > 0 && token.data == NULL)) {
        return false;
    }
    const uint64_t length = token.length;
    return HawkSHA256Update(context, &length, sizeof(length)) &&
        HawkSHA256Update(context, token.data, token.length);
}

static bool HawkHashFileObject(
    const es_file_t *file,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
) {
    if (file == NULL) {
        return false;
    }
    HawkSHA256Context context;
    HawkSHA256Initialize(&context);
    static const char domain[] = "hawk.macos.file-object.v1";
    const struct stat *metadata = &file->stat;
    const bool accepted =
        HawkSHA256Update(&context, domain, sizeof(domain)) &&
        HawkSHA256Update(&context, &metadata->st_dev, sizeof(metadata->st_dev)) &&
        HawkSHA256Update(&context, &metadata->st_ino, sizeof(metadata->st_ino)) &&
        HawkSHA256Update(&context, &metadata->st_gen, sizeof(metadata->st_gen)) &&
        HawkSHA256Update(
            &context,
            &metadata->st_birthtimespec,
            sizeof(metadata->st_birthtimespec)
        );
    if (!accepted) {
        return false;
    }
    HawkSHA256Finalize(&context, digest);
    return true;
}

static bool HawkHashNewPathObject(
    const es_file_t *directory,
    es_string_token_t filename,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
) {
    uint8_t directoryIdentity[HAWK_FLOOR_HASH_BYTES];
    if (!HawkHashFileObject(directory, directoryIdentity)) {
        return false;
    }
    HawkSHA256Context context;
    HawkSHA256Initialize(&context);
    static const char domain[] = "hawk.macos.new-path-object.v1";
    const bool accepted =
        HawkSHA256Update(&context, domain, sizeof(domain)) &&
        HawkSHA256Update(&context, directoryIdentity, sizeof(directoryIdentity)) &&
        HawkHashToken(&context, filename);
    memset(directoryIdentity, 0, sizeof(directoryIdentity));
    if (!accepted) {
        return false;
    }
    HawkSHA256Finalize(&context, digest);
    return true;
}

static bool HawkHashPathContext(
    const es_file_t *file,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
) {
    if (file == NULL) {
        return false;
    }
    HawkSHA256Context context;
    HawkSHA256Initialize(&context);
    static const char domain[] = "hawk.macos.path-context.v1";
    const bool accepted =
        HawkSHA256Update(&context, domain, sizeof(domain)) &&
        HawkSHA256Update(
            &context,
            &file->path_truncated,
            sizeof(file->path_truncated)
        ) &&
        HawkHashToken(&context, file->path);
    if (!accepted) {
        return false;
    }
    HawkSHA256Finalize(&context, digest);
    return true;
}

static bool HawkHashNewPathContext(
    const es_file_t *directory,
    es_string_token_t filename,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
) {
    if (directory == NULL || directory->path_truncated ||
        directory->path.length == 0 || directory->path.data == NULL ||
        directory->path.data[0] != '/' || filename.length == 0 ||
        filename.data == NULL || filename.length > HAWK_MAC_MAX_ES_TOKEN_BYTES ||
        memchr(filename.data, '/', filename.length) != NULL ||
        memchr(filename.data, '\0', filename.length) != NULL) return false;
    const bool separator = directory->path.data[directory->path.length - 1] != '/';
    if (directory->path.length > HAWK_MAC_MAX_ES_TOKEN_BYTES - filename.length -
        (separator ? 1U : 0U)) return false;
    const uint64_t pathLength = directory->path.length + filename.length +
        (separator ? 1U : 0U);
    const bool truncated = false;
    HawkSHA256Context context;
    HawkSHA256Initialize(&context);
    static const char domain[] = "hawk.macos.path-context.v1";
    const bool accepted = HawkSHA256Update(&context, domain, sizeof(domain)) &&
        HawkSHA256Update(&context, &truncated, sizeof(truncated)) &&
        HawkSHA256Update(&context, &pathLength, sizeof(pathLength)) &&
        HawkSHA256Update(&context, directory->path.data, directory->path.length) &&
        (!separator || HawkSHA256Update(&context, "/", 1)) &&
        HawkSHA256Update(&context, filename.data, filename.length);
    if (!accepted) return false;
    HawkSHA256Finalize(&context, digest);
    return true;
}

static bool HawkHashProcessInstance(
    const es_message_t *message,
    const es_process_t *process,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
) {
    if (message == NULL || process == NULL) {
        return false;
    }
    HawkSHA256Context context;
    HawkSHA256Initialize(&context);
    static const char domain[] = "hawk.macos.process-instance.v1";
    const int pidVersion = audit_token_to_pidversion(process->audit_token);
    bool accepted =
        HawkSHA256Update(&context, domain, sizeof(domain)) &&
        HawkSHA256Update(
            &context,
            &process->audit_token,
            sizeof(process->audit_token)
        ) &&
        HawkSHA256Update(&context, &pidVersion, sizeof(pidVersion));
    if (accepted && message->version >= 3) {
        accepted = HawkSHA256Update(
            &context,
            &process->start_time,
            sizeof(process->start_time)
        );
    }
    if (accepted && message->version >= 4) {
        accepted = HawkSHA256Update(
            &context,
            &process->responsible_audit_token,
            sizeof(process->responsible_audit_token)
        ) && HawkSHA256Update(
            &context,
            &process->parent_audit_token,
            sizeof(process->parent_audit_token)
        );
    }
    if (!accepted) {
        return false;
    }
    HawkSHA256Finalize(&context, digest);
    return true;
}

bool HawkBuildStableCodeIdentity(
    const es_process_t *process,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
) {
    return HawkMacCodeIdentityFromESProcess(process, digest);
}

static bool HawkResolveEventResources(
    const es_message_t *message,
    uint8_t stableResource[HAWK_FLOOR_HASH_BYTES],
    uint8_t resourceReference[HAWK_FLOOR_HASH_BYTES],
    uint8_t destinationReference[HAWK_FLOOR_HASH_BYTES]
) {
    const es_file_t *file = NULL;
    switch (message->event_type) {
        case ES_EVENT_TYPE_AUTH_OPEN:
            file = message->event.open.file;
            break;
        case ES_EVENT_TYPE_AUTH_CREATE:
            if (message->event.create.destination_type ==
                ES_DESTINATION_TYPE_EXISTING_FILE) {
                file = message->event.create.destination.existing_file;
                break;
            }
            return HawkHashNewPathObject(
                    message->event.create.destination.new_path.dir,
                    message->event.create.destination.new_path.filename,
                    stableResource
                ) && HawkHashNewPathContext(
                    message->event.create.destination.new_path.dir,
                    message->event.create.destination.new_path.filename,
                    resourceReference
                );
        case ES_EVENT_TYPE_AUTH_RENAME:
            file = message->event.rename.source;
            if (message->event.rename.destination_type ==
                ES_DESTINATION_TYPE_EXISTING_FILE) {
                if (!HawkHashFileObject(
                        message->event.rename.destination.existing_file,
                        destinationReference
                    )) {
                    return false;
                }
            } else if (!HawkHashNewPathContext(
                    message->event.rename.destination.new_path.dir,
                    message->event.rename.destination.new_path.filename,
                    destinationReference
                )) {
                return false;
            }
            break;
        case ES_EVENT_TYPE_AUTH_UNLINK:
            file = message->event.unlink.target;
            break;
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            file = message->event.truncate.target;
            break;
        case ES_EVENT_TYPE_AUTH_MMAP:
            file = message->event.mmap.source;
            break;
        case ES_EVENT_TYPE_AUTH_LINK:
            file = message->event.link.source;
            if (!HawkHashNewPathContext(
                    message->event.link.target_dir,
                    message->event.link.target_filename,
                    destinationReference
                )) {
                return false;
            }
            break;
        case ES_EVENT_TYPE_AUTH_SETEXTATTR:
            file = message->event.setextattr.target;
            break;
        case ES_EVENT_TYPE_AUTH_SETFLAGS:
            file = message->event.setflags.target;
            break;
        case ES_EVENT_TYPE_AUTH_SETMODE:
            file = message->event.setmode.target;
            break;
        case ES_EVENT_TYPE_AUTH_SETOWNER:
            file = message->event.setowner.target;
            break;
        case ES_EVENT_TYPE_AUTH_CLONE:
            if (!HawkHashNewPathObject(
                    message->event.clone.target_dir,
                    message->event.clone.target_name,
                    stableResource
                ) || !HawkHashNewPathContext(
                    message->event.clone.target_dir,
                    message->event.clone.target_name,
                    resourceReference
                ) || !HawkHashFileObject(
                    message->event.clone.source,
                    destinationReference
                )) {
                return false;
            }
            return true;
        case ES_EVENT_TYPE_AUTH_COPYFILE:
            if (message->event.copyfile.target_file != NULL) {
                if (!HawkHashFileObject(
                        message->event.copyfile.target_file,
                        stableResource
                    ) || !HawkHashPathContext(
                        message->event.copyfile.target_file,
                        resourceReference
                    )) {
                    return false;
                }
            } else if (!HawkHashNewPathObject(
                    message->event.copyfile.target_dir,
                    message->event.copyfile.target_name,
                    stableResource
                ) || !HawkHashNewPathContext(
                    message->event.copyfile.target_dir,
                    message->event.copyfile.target_name,
                    resourceReference
                )) {
                return false;
            }
            return HawkHashFileObject(
                message->event.copyfile.source,
                destinationReference
            );
        case ES_EVENT_TYPE_AUTH_EXEC:
            file = message->event.exec.target->executable;
            break;
        default:
            return false;
    }
    return HawkHashFileObject(file, stableResource) &&
        HawkHashPathContext(file, resourceReference);
}

static uint64_t HawkRequestedRights(
    const es_message_t *message,
    HawkFloorPrimitive primitive
) {
    if (message->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
        return (uint64_t)(uint32_t)message->event.open.fflag;
    }
    if (message->event_type == ES_EVENT_TYPE_AUTH_MMAP) {
        return (uint64_t)(uint32_t)message->event.mmap.protection |
            ((uint64_t)(uint32_t)message->event.mmap.max_protection << 16U) |
            ((uint64_t)(uint32_t)message->event.mmap.flags << 32U);
    }
    if (message->event_type == ES_EVENT_TYPE_AUTH_CREATE) {
        return message->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH
            ? (uint64_t)message->event.create.destination.new_path.mode
            : (1ULL << (uint32_t)primitive);
    }
    if (message->event_type == ES_EVENT_TYPE_AUTH_SETFLAGS) {
        return (uint64_t)message->event.setflags.flags;
    }
    if (message->event_type == ES_EVENT_TYPE_AUTH_SETMODE) {
        return (uint64_t)message->event.setmode.mode;
    }
    if (message->event_type == ES_EVENT_TYPE_AUTH_SETOWNER) {
        return (uint64_t)message->event.setowner.uid |
            ((uint64_t)message->event.setowner.gid << 32U);
    }
    if (message->event_type == ES_EVENT_TYPE_AUTH_COPYFILE) {
        return (uint64_t)(uint32_t)message->event.copyfile.flags |
            ((uint64_t)message->event.copyfile.mode << 32U);
    }
    return 1ULL << (uint32_t)primitive;
}

static uint64_t HawkMachTimeToNanoseconds(uint64_t absoluteTime) {
    mach_timebase_info_data_t timebase;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.denom == 0) {
        return 0;
    }
    const __uint128_t scaled = (__uint128_t)absoluteTime * timebase.numer;
    return (uint64_t)(scaled / timebase.denom);
}

static bool HawkHashEventArguments(
    const es_message_t *message,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
) {
    HawkSHA256Context context;
    HawkSHA256Initialize(&context);
    static const char domain[] = "hawk.macos.endpoint-event-arguments.v1";
    bool accepted =
        HawkSHA256Update(&context, domain, sizeof(domain)) &&
        HawkSHA256Update(&context, &message->event_type, sizeof(message->event_type));
    switch (message->event_type) {
        case ES_EVENT_TYPE_AUTH_OPEN:
            accepted = accepted && HawkSHA256Update(
                &context,
                &message->event.open.fflag,
                sizeof(message->event.open.fflag)
            );
            break;
        case ES_EVENT_TYPE_AUTH_MMAP:
            accepted = accepted &&
                HawkSHA256Update(&context, &message->event.mmap.protection,
                    sizeof(message->event.mmap.protection)) &&
                HawkSHA256Update(&context, &message->event.mmap.max_protection,
                    sizeof(message->event.mmap.max_protection)) &&
                HawkSHA256Update(&context, &message->event.mmap.flags,
                    sizeof(message->event.mmap.flags)) &&
                HawkSHA256Update(&context, &message->event.mmap.file_pos,
                    sizeof(message->event.mmap.file_pos));
            break;
        case ES_EVENT_TYPE_AUTH_SETEXTATTR:
            accepted = accepted && HawkHashToken(
                &context,
                message->event.setextattr.extattr
            );
            break;
        case ES_EVENT_TYPE_AUTH_SETFLAGS:
            accepted = accepted && HawkSHA256Update(
                &context,
                &message->event.setflags.flags,
                sizeof(message->event.setflags.flags)
            );
            break;
        case ES_EVENT_TYPE_AUTH_SETMODE:
            accepted = accepted && HawkSHA256Update(
                &context,
                &message->event.setmode.mode,
                sizeof(message->event.setmode.mode)
            );
            break;
        case ES_EVENT_TYPE_AUTH_SETOWNER:
            accepted = accepted &&
                HawkSHA256Update(&context, &message->event.setowner.uid,
                    sizeof(message->event.setowner.uid)) &&
                HawkSHA256Update(&context, &message->event.setowner.gid,
                    sizeof(message->event.setowner.gid));
            break;
        case ES_EVENT_TYPE_AUTH_COPYFILE:
            accepted = accepted &&
                HawkSHA256Update(&context, &message->event.copyfile.mode,
                    sizeof(message->event.copyfile.mode)) &&
                HawkSHA256Update(&context, &message->event.copyfile.flags,
                    sizeof(message->event.copyfile.flags));
            break;
        default:
            break;
    }
    if (!accepted) {
        return false;
    }
    HawkSHA256Finalize(&context, digest);
    return true;
}

static bool HawkHashCanonicalAction(
    HawkFloorRequest *request,
    const es_message_t *message
) {
    uint8_t eventArguments[HAWK_FLOOR_HASH_BYTES];
    if (!HawkHashEventArguments(message, eventArguments)) {
        return false;
    }
    HawkSHA256Context context;
    HawkSHA256Initialize(&context);
    static const char domain[] = "hawk.endpoint-floor.canonical-action.v1";
    const bool accepted =
        HawkSHA256Update(&context, domain, sizeof(domain)) &&
        HawkSHA256Update(&context, &request->primitive, sizeof(request->primitive)) &&
        HawkSHA256Update(
            &context,
            request->processInstanceHash,
            HAWK_FLOOR_HASH_BYTES
        ) &&
        HawkSHA256Update(
            &context,
            request->stableResourceIdentityHash,
            HAWK_FLOOR_HASH_BYTES
        ) &&
        HawkSHA256Update(
            &context,
            request->resourceReferenceHash,
            HAWK_FLOOR_HASH_BYTES
        ) &&
        HawkSHA256Update(
            &context,
            request->destinationReferenceHash,
            HAWK_FLOOR_HASH_BYTES
        ) &&
        HawkSHA256Update(
            &context,
            request->binaryIdentityHash,
            HAWK_FLOOR_HASH_BYTES
        ) &&
        HawkSHA256Update(&context, eventArguments, sizeof(eventArguments)) &&
        HawkSHA256Update(
            &context,
            &request->requestedRights,
            sizeof(request->requestedRights)
        ) &&
        HawkSHA256Update(&context, &request->policyEpoch, sizeof(request->policyEpoch));
    memset(eventArguments, 0, sizeof(eventArguments));
    if (!accepted) {
        return false;
    }
    HawkSHA256Finalize(&context, request->canonicalActionHash);
    return true;
}

bool HawkBuildRequestFromESMessage(
    const es_message_t *message,
    HawkFloorPrimitive primitive,
    HawkFloorRequest *request
) {
    if (message == NULL || request == NULL || message->process == NULL ||
        primitive < HAWK_FLOOR_FILE_OPEN ||
        primitive >= HAWK_FLOOR_PRIMITIVE_COUNT) {
        return false;
    }
    const es_process_t *subject = message->event_type == ES_EVENT_TYPE_AUTH_EXEC
        ? message->event.exec.target
        : message->process;
    if (subject == NULL) {
        return false;
    }
    memset(request, 0, sizeof(*request));
    request->schemaVersion = HAWK_FLOOR_SCHEMA_VERSION;
    request->primitive = primitive;
    request->requestedRights = HawkRequestedRights(message, primitive);
    request->deadlineMonotonicNs = HawkMachTimeToNanoseconds(message->deadline);
    uint8_t targetIdentity[HAWK_FLOOR_HASH_BYTES];
    if (request->requestedRights == 0 || request->deadlineMonotonicNs == 0 ||
        !HawkMacCopyPolicyBinding(
            request->tenantHash,
            request->deviceHash,
            &request->policyEpoch
        ) ||
        !HawkHashProcessInstance(message, subject, request->processInstanceHash) ||
        !HawkBuildStableCodeIdentity(subject, targetIdentity) ||
        !HawkResolveEventResources(
            message,
            request->stableResourceIdentityHash,
            request->resourceReferenceHash,
            request->destinationReferenceHash
        )) {
        memset(request, 0, sizeof(*request));
        return false;
    }
    if (message->event_type == ES_EVENT_TYPE_AUTH_EXEC) {
        if (HawkMacIsBinaryIdentityGoverned(targetIdentity)) {
            memcpy(request->binaryIdentityHash, targetIdentity, HAWK_FLOOR_HASH_BYTES);
        } else if (!HawkMacProcessLineageLookup(message->process->audit_token,
                                                request->binaryIdentityHash)) {
            if (!HawkBuildStableCodeIdentity(message->process,
                                             request->binaryIdentityHash)) return false;
        }
    } else if (!HawkMacProcessLineageLookup(subject->audit_token,
                                            request->binaryIdentityHash)) {
        memcpy(request->binaryIdentityHash, targetIdentity, HAWK_FLOOR_HASH_BYTES);
    }
    memset(targetIdentity, 0, sizeof(targetIdentity));
    memcpy(
        request->processIdentityHash,
        request->binaryIdentityHash,
        HAWK_FLOOR_HASH_BYTES
    );
    if (!HawkHashCanonicalAction(request, message)) {
        memset(request, 0, sizeof(*request));
        return false;
    }
    return true;
}
