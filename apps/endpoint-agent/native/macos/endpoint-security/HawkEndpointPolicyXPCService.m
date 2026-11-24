#import "HawkEndpointPolicyXPCService.h"

#import <Foundation/Foundation.h>
#import <mach/mach_time.h>
#import <time.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

#import "../shared/HawkMacPolicyBridge.h"
#import "../shared/HawkMacPolicyWire.h"
#import "HawkMacProcessLineage.h"

@protocol HawkEndpointPolicyDelivery
- (void)installPolicyEnvelope:(NSData *)envelope
                         reply:(void (^)(BOOL installed, NSInteger reason))reply;
- (void)copyPolicyHealthWithReply:(void (^)(NSDictionary<NSString *, id> *health))reply;
@end

static uint64_t HawkEndpointMonotonicNanoseconds(void) {
    mach_timebase_info_data_t timebase;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.denom == 0) {
        return 0;
    }
    const __uint128_t scaled = (__uint128_t)mach_absolute_time() * timebase.numer;
    return (uint64_t)(scaled / timebase.denom);
}

static uint64_t HawkEndpointUnixSeconds(void) {
    const time_t now = time(NULL);
    return now > 0 ? (uint64_t)now : 0;
}

@interface HawkEndpointPolicyReceiver : NSObject <HawkEndpointPolicyDelivery>
@property(nonatomic, copy) NSData *pinnedPublicKey;
@property(nonatomic, copy) NSString *envelopeDigest;
@end

static NSString *HawkHexDigest(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *rendered = [NSMutableString stringWithCapacity:64];
    for (size_t index = 0; index < sizeof(digest); ++index)
        [rendered appendFormat:@"%02x", digest[index]];
    return rendered;
}

static NSString *HawkSignedTeamIdentifier(void) {
    SecCodeRef selfCode = NULL;
    CFDictionaryRef information = NULL;
    NSString *team = nil;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &selfCode) == errSecSuccess &&
        selfCode != NULL &&
        SecCodeCheckValidity(selfCode, kSecCSStrictValidate, NULL) == errSecSuccess &&
        SecCodeCopySigningInformation(selfCode, kSecCSSigningInformation,
            &information) == errSecSuccess && information != NULL) {
        id value = (__bridge id)CFDictionaryGetValue(information,
            kSecCodeInfoTeamIdentifier);
        if ([value isKindOfClass:NSString.class]) team = value;
    }
    if (information != NULL) CFRelease(information);
    if (selfCode != NULL) CFRelease(selfCode);
    return team;
}

@implementation HawkEndpointPolicyReceiver
- (void)installPolicyEnvelope:(NSData *)envelope
                         reply:(void (^)(BOOL installed, NSInteger reason))reply {
    if (envelope.length == 0 ||
        envelope.length > HAWK_MAC_POLICY_ENVELOPE_MAX_BYTES ||
        self.pinnedPublicKey.length != HAWK_MAC_POLICY_PUBLIC_KEY_X963_BYTES) {
        reply(NO, 1);
        return;
    }
    const uint64_t now = HawkEndpointMonotonicNanoseconds();
    const uint64_t unixNow = HawkEndpointUnixSeconds();
    const BOOL installed = now != 0 && HawkMacVerifyAndInstallPolicyEnvelope(
        envelope.bytes,
        envelope.length,
        self.pinnedPublicKey.bytes,
        self.pinnedPublicKey.length,
        true,
        now,
        unixNow
    );
    if (installed) self.envelopeDigest = HawkHexDigest(envelope);
    reply(installed, installed ? 0 : 2);
}

- (void)copyPolicyHealthWithReply:(void (^)(NSDictionary<NSString *, id> *health))reply {
    HawkMacPolicyHealth health;
    HawkMacProcessLineageHealth lineageHealth;
    memset(&health, 0, sizeof(health));
    memset(&lineageHealth, 0, sizeof(lineageHealth));
    if (!HawkMacCopyPolicyHealth(&health) ||
        !HawkMacProcessLineageCopyHealth(&lineageHealth)) {
        reply(@{@"schema_version": @1, @"active": @NO});
        return;
    }
    const size_t versionLength = strnlen(
        health.policyVersion,
        HAWK_FLOOR_REFERENCE_BYTES
    );
    NSString *policyVersion = [[NSString alloc]
        initWithBytes:health.policyVersion
        length:versionLength
        encoding:NSUTF8StringEncoding] ?: @"";
    NSData *digest = [NSData dataWithBytes:health.bundleDigest
                                    length:HAWK_FLOOR_HASH_BYTES];
    reply(@{
        @"schema_version": @(health.schemaVersion),
        @"active": @(health.active),
        @"authenticated_peer": @(health.authenticatedPeer),
        @"signature_verified": @(health.signatureVerified),
        @"signer_pin_verified": @(health.signerPinVerified),
        @"configuration_integrity_valid": @(health.configurationIntegrityValid),
        @"policy_epoch": @(health.policyEpoch),
        @"delivery_sequence": @(health.deliverySequence),
        @"expires_at_monotonic_ns": @(health.expiresAtMonotonicNs),
        @"issued_at_unix_seconds": @(health.issuedAtUnixSeconds),
        @"expires_at_unix_seconds": @(health.expiresAtUnixSeconds),
        @"policy_current": @(health.policyCurrent),
        @"lineage_occupancy": @(lineageHealth.occupancy),
        @"lineage_record_failure_count": @(lineageHealth.recordFailureCount),
        @"mode": @(health.mode),
        @"would_block_count": @(health.wouldBlockCount),
        @"accepted_delivery_count": @(health.acceptedDeliveryCount),
        @"rejected_delivery_count": @(health.rejectedDeliveryCount),
        @"last_rejection_reason": @(health.lastRejectionReason),
        @"policy_version": policyVersion,
        @"bundle_digest": [digest base64EncodedStringWithOptions:0],
        @"policy_digest": self.envelopeDigest ?: @"",
        @"signing_key_digest": HawkHexDigest(self.pinnedPublicKey),
        @"bundle_id": NSBundle.mainBundle.bundleIdentifier ?: @"",
        @"team_id": HawkSignedTeamIdentifier() ?: @"",
        @"contains_secret_material": @NO,
    });
}
@end

@interface HawkEndpointPolicyListenerDelegate : NSObject <NSXPCListenerDelegate>
@property(nonatomic, strong) HawkEndpointPolicyReceiver *receiver;
@end

@implementation HawkEndpointPolicyListenerDelegate
- (BOOL)listener:(NSXPCListener *)listener
    shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    (void)listener;
    newConnection.exportedInterface = [NSXPCInterface
        interfaceWithProtocol:@protocol(HawkEndpointPolicyDelivery)];
    newConnection.exportedObject = self.receiver;
    [newConnection resume];
    return YES;
}
@end

static NSXPCListener *sPolicyListener;
static HawkEndpointPolicyListenerDelegate *sPolicyListenerDelegate;

int HawkStartEndpointPolicyXPCService(void) {
    NSBundle *bundle = NSBundle.mainBundle;
    NSString *serviceName = [bundle
        objectForInfoDictionaryKey:@"NSEndpointSecurityMachServiceName"];
    NSString *peerRequirement = [bundle
        objectForInfoDictionaryKey:@"HawkPolicyPeerRequirement"];
    NSString *encodedPublicKey = [bundle
        objectForInfoDictionaryKey:@"HawkPolicySigningPublicKeyX963Base64"];
    NSString *team = HawkSignedTeamIdentifier();
    NSString *expectedService = [NSString stringWithFormat:
        @"%@.ai.hawk.endpoint.endpoint-security.policy", team ?: @""];
    if (![bundle.bundleIdentifier isEqualToString:@"ai.hawk.endpoint.endpoint-security"] ||
        team.length != 10 || ![serviceName isEqualToString:expectedService] ||
        ![peerRequirement isEqualToString:[NSString stringWithFormat:
            @"anchor apple generic and identifier \"ai.hawk.endpoint.host\" and certificate leaf[subject.OU] = \"%@\"", team]] ||
        encodedPublicKey.length == 0) {
        return 1;
    }
    NSData *publicKey = [[NSData alloc]
        initWithBase64EncodedString:encodedPublicKey
        options:0];
    if (publicKey.length != HAWK_MAC_POLICY_PUBLIC_KEY_X963_BYTES ||
        ((const uint8_t *)publicKey.bytes)[0] != 0x04U) {
        return 2;
    }
    @try {
        sPolicyListener = [[NSXPCListener alloc]
            initWithMachServiceName:serviceName];
        [sPolicyListener setConnectionCodeSigningRequirement:peerRequirement];
    } @catch (NSException *exception) {
        (void)exception;
        sPolicyListener = nil;
        return 3;
    }
    HawkEndpointPolicyReceiver *receiver = [HawkEndpointPolicyReceiver new];
    receiver.pinnedPublicKey = publicKey;
    sPolicyListenerDelegate = [HawkEndpointPolicyListenerDelegate new];
    sPolicyListenerDelegate.receiver = receiver;
    sPolicyListener.delegate = sPolicyListenerDelegate;
    [sPolicyListener activate];
    return 0;
}
