#ifndef HAWK_MAC_NETWORK_BRIDGE_H
#define HAWK_MAC_NETWORK_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

typedef enum HawkMacNetworkVerdict {
    HAWK_MAC_NETWORK_VERDICT_BLOCK = 0,
    HAWK_MAC_NETWORK_VERDICT_ALLOW = 1,
    HAWK_MAC_NETWORK_VERDICT_LOCAL_RETRY_REQUIRED = 2
} HawkMacNetworkVerdict;

int32_t HawkEvaluateNetworkFlow(
    const uint8_t *sourceProcessAuditToken,
    size_t sourceProcessAuditTokenLength,
    const uint8_t *sourceApplicationAuditToken,
    size_t sourceApplicationAuditTokenLength,
    const uint8_t *destinationHost,
    size_t destinationHostLength,
    uint16_t destinationPort,
    int32_t socketProtocol,
    int32_t socketFamily
);

#endif
