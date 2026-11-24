#ifndef HAWK_WINDOWS_NETWORK_IDENTITY_H
#define HAWK_WINDOWS_NETWORK_IDENTITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#define HAWK_WINDOWS_INLINE static __inline
#else
#define HAWK_WINDOWS_INLINE static inline
#endif

#pragma pack(push, 1)
typedef struct HawkWindowsNetworkDestinationMaterial {
    uint8_t domain[40];
    uint8_t family;
    uint8_t protocol;
    uint8_t remotePortNetworkOrder[2];
    uint8_t remoteInterfaceIndexNetworkOrder[4];
    uint8_t remoteAddressNetworkOrder[16];
} HawkWindowsNetworkDestinationMaterial;
#pragma pack(pop)

HAWK_WINDOWS_INLINE bool HawkWindowsBuildNetworkDestinationMaterial(
    uint8_t family,
    uint8_t protocol,
    uint16_t remotePortHostOrder,
    uint32_t remoteInterfaceIndexHostOrder,
    const uint8_t *remoteAddressNetworkOrder,
    size_t remoteAddressLength,
    HawkWindowsNetworkDestinationMaterial *material,
    uint64_t *requestedRights
) {
    static const uint8_t domain[] = "hawk.windows.network-destination.v3";
    const size_t expectedAddressLength = family == 4U ? 4U :
        (family == 6U ? 16U : 0U);
    if ((protocol != 6U && protocol != 17U) ||
        remotePortHostOrder == 0U ||
        remoteInterfaceIndexHostOrder == 0U ||
        remoteAddressNetworkOrder == NULL || material == NULL ||
        requestedRights == NULL || expectedAddressLength == 0U ||
        remoteAddressLength != expectedAddressLength ||
        sizeof(domain) > sizeof(material->domain)) {
        return false;
    }

    uint8_t *materialBytes = (uint8_t *)material;
    for (size_t index = 0; index < sizeof(*material); ++index) {
        materialBytes[index] = 0U;
    }
    for (size_t index = 0; index < sizeof(domain); ++index) {
        material->domain[index] = domain[index];
    }
    material->family = family;
    material->protocol = protocol;
    material->remotePortNetworkOrder[0] =
        (uint8_t)(remotePortHostOrder >> 8U);
    material->remotePortNetworkOrder[1] =
        (uint8_t)remotePortHostOrder;
    material->remoteInterfaceIndexNetworkOrder[0] =
        (uint8_t)(remoteInterfaceIndexHostOrder >> 24U);
    material->remoteInterfaceIndexNetworkOrder[1] =
        (uint8_t)(remoteInterfaceIndexHostOrder >> 16U);
    material->remoteInterfaceIndexNetworkOrder[2] =
        (uint8_t)(remoteInterfaceIndexHostOrder >> 8U);
    material->remoteInterfaceIndexNetworkOrder[3] =
        (uint8_t)remoteInterfaceIndexHostOrder;
    for (size_t index = 0; index < remoteAddressLength; ++index) {
        material->remoteAddressNetworkOrder[index] =
            remoteAddressNetworkOrder[index];
    }
    *requestedRights = ((uint64_t)family << 56U) |
        ((uint64_t)protocol << 48U) |
        (uint64_t)remotePortHostOrder;
    return *requestedRights != 0U;
}

#undef HAWK_WINDOWS_INLINE

#endif
