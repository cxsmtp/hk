#ifndef HAWK_MAC_ENDPOINT_REQUEST_H
#define HAWK_MAC_ENDPOINT_REQUEST_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdbool.h>

#include "../../shared/HawkFloorDecisionEngine.h"

bool HawkBuildRequestFromESMessage(
    const es_message_t *message,
    HawkFloorPrimitive primitive,
    HawkFloorRequest *request
);

bool HawkBuildStableCodeIdentity(
    const es_process_t *process,
    uint8_t digest[HAWK_FLOOR_HASH_BYTES]
);

#endif
