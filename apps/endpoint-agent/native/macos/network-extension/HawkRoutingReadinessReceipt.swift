import CryptoKit
import Foundation

enum HawkRoutingReceiptError: Error {
    case invalidApplicationScope
    case invalidDestinationScope
    case invalidPolicyEpoch
    case invalidScopeDigest
    case invalidNonce
    case invalidLifetime
    case invalidWireRepresentation
}

struct HawkManagedRoutingScopeMaterial {
    private static let maximumApplications = 256
    private static let maximumDestinations = 256

    let applicationSigningIdentifiers: [String]
    let destinationHostSuffixes: [String]
    let policyEpoch: UInt64
    let semanticInspectionRequired: Bool

    init(
        applicationSigningIdentifiers: [String],
        destinationHostSuffixes: [String],
        policyEpoch: UInt64,
        semanticInspectionRequired: Bool
    ) throws {
        let applications = try Set(
            applicationSigningIdentifiers.map(Self.normalizeApplicationIdentifier)
        ).sorted()
        let destinations = try Set(
            destinationHostSuffixes.map(Self.normalizeDestinationSuffix)
        ).sorted()

        guard !applications.isEmpty,
              applications.count <= Self.maximumApplications else {
            throw HawkRoutingReceiptError.invalidApplicationScope
        }
        guard !destinations.isEmpty,
              destinations.count <= Self.maximumDestinations else {
            throw HawkRoutingReceiptError.invalidDestinationScope
        }
        guard policyEpoch > 0 else {
            throw HawkRoutingReceiptError.invalidPolicyEpoch
        }

        self.applicationSigningIdentifiers = applications
        self.destinationHostSuffixes = destinations
        self.policyEpoch = policyEpoch
        self.semanticInspectionRequired = semanticInspectionRequired
    }

    func canonicalDigest() -> Data {
        var material = Data("hawk-routing-scope-v1\0".utf8)
        material.appendUInt32(UInt32(applicationSigningIdentifiers.count))
        for identifier in applicationSigningIdentifiers {
            material.appendLengthPrefixedASCII(identifier)
        }
        material.appendUInt32(UInt32(destinationHostSuffixes.count))
        for suffix in destinationHostSuffixes {
            material.appendLengthPrefixedASCII(suffix)
        }
        material.appendUInt64(policyEpoch)
        material.append(semanticInspectionRequired ? 1 : 0)
        return Data(SHA256.hash(data: material))
    }

    private static func normalizeApplicationIdentifier(_ value: String) throws -> String {
        guard !value.isEmpty,
              value.utf8.count <= 255,
              value.utf8.allSatisfy({
                  ($0 >= 0x30 && $0 <= 0x39)
                      || ($0 >= 0x41 && $0 <= 0x5a)
                      || ($0 >= 0x61 && $0 <= 0x7a)
                      || $0 == 0x2d
                      || $0 == 0x2e
              }),
              !value.hasPrefix("."),
              !value.hasSuffix("."),
              !value.contains("..") else {
            throw HawkRoutingReceiptError.invalidApplicationScope
        }
        return value
    }

    static func normalizeDestinationSuffix(_ value: String) throws -> String {
        var normalized = value.lowercased()
        if normalized.hasSuffix(".") {
            normalized.removeLast()
        }
        let labels = normalized.split(separator: ".", omittingEmptySubsequences: false)
        guard !normalized.isEmpty,
              normalized.utf8.count <= 253,
              labels.allSatisfy({ label in
                  guard !label.isEmpty,
                        label.utf8.count <= 63,
                        let first = label.utf8.first,
                        let last = label.utf8.last,
                        Self.isASCIIAlphaNumeric(first),
                        Self.isASCIIAlphaNumeric(last) else {
                      return false
                  }
                  return label.utf8.allSatisfy({ byte in
                      Self.isASCIIAlphaNumeric(byte) || byte == 0x2d
                  })
              }) else {
            throw HawkRoutingReceiptError.invalidDestinationScope
        }
        return normalized
    }

    private static func isASCIIAlphaNumeric(_ value: UInt8) -> Bool {
        (value >= 0x30 && value <= 0x39) || (value >= 0x61 && value <= 0x7a)
    }
}

struct HawkRoutingBrokerKeyAuthorization {
    static let maximumLifetimeSeconds: UInt64 = 2_592_000
    static let maximumFutureSkewSeconds: UInt64 = 60

    private static let magic = Data("HAWKRK01".utf8)
    private static let version: UInt32 = 1
    private static let wireSize = 84

    let issuedAtUnixSeconds: UInt64
    let expiresAtUnixSeconds: UInt64
    let keyEpoch: UInt64
    let brokerPublicKeyDigest: Data
    let nonce: Data

    init(
        issuedAtUnixSeconds: UInt64,
        expiresAtUnixSeconds: UInt64,
        keyEpoch: UInt64,
        brokerPublicKeyDigest: Data,
        nonce: Data
    ) throws {
        guard issuedAtUnixSeconds > 0,
              expiresAtUnixSeconds > issuedAtUnixSeconds,
              expiresAtUnixSeconds - issuedAtUnixSeconds <= Self.maximumLifetimeSeconds else {
            throw HawkRoutingReceiptError.invalidLifetime
        }
        guard keyEpoch > 0 else {
            throw HawkRoutingReceiptError.invalidPolicyEpoch
        }
        guard brokerPublicKeyDigest.count == SHA256.byteCount else {
            throw HawkRoutingReceiptError.invalidScopeDigest
        }
        guard nonce.count == 16,
              nonce.contains(where: { $0 != 0 }) else {
            throw HawkRoutingReceiptError.invalidNonce
        }
        self.issuedAtUnixSeconds = issuedAtUnixSeconds
        self.expiresAtUnixSeconds = expiresAtUnixSeconds
        self.keyEpoch = keyEpoch
        self.brokerPublicKeyDigest = brokerPublicKeyDigest
        self.nonce = nonce
    }

    func serialized() throws -> Data {
        var wire = Self.magic
        wire.appendUInt32(Self.version)
        wire.appendUInt64(issuedAtUnixSeconds)
        wire.appendUInt64(expiresAtUnixSeconds)
        wire.appendUInt64(keyEpoch)
        wire.append(brokerPublicKeyDigest)
        wire.append(nonce)
        guard wire.count == Self.wireSize else {
            throw HawkRoutingReceiptError.invalidWireRepresentation
        }
        return wire
    }

    static func parse(_ wire: Data) throws -> Self {
        guard wire.count == wireSize,
              wire.prefix(magic.count) == magic,
              wire.readUInt32(at: 8) == version else {
            throw HawkRoutingReceiptError.invalidWireRepresentation
        }
        return try Self(
            issuedAtUnixSeconds: wire.readUInt64(at: 12),
            expiresAtUnixSeconds: wire.readUInt64(at: 20),
            keyEpoch: wire.readUInt64(at: 28),
            brokerPublicKeyDigest: wire.subdata(in: 36..<68),
            nonce: wire.subdata(in: 68..<84)
        )
    }
}

enum HawkRoutingBrokerAuthorizationVerifier {
    static func verify(
        authorization: Data,
        signatureDER: Data,
        trustRootPublicKeyX963: Data,
        brokerPublicKeyX963: Data,
        nowUnixSeconds: UInt64
    ) -> Bool {
        verifiedAuthorization(
            authorization: authorization,
            signatureDER: signatureDER,
            trustRootPublicKeyX963: trustRootPublicKeyX963,
            brokerPublicKeyX963: brokerPublicKeyX963,
            nowUnixSeconds: nowUnixSeconds
        ) != nil
    }

    static func verifiedAuthorization(
        authorization: Data,
        signatureDER: Data,
        trustRootPublicKeyX963: Data,
        brokerPublicKeyX963: Data,
        nowUnixSeconds: UInt64
    ) -> HawkRoutingBrokerKeyAuthorization? {
        guard authorization.count == 84,
              signatureDER.count >= 64,
              signatureDER.count <= 80,
              trustRootPublicKeyX963.count == 65,
              brokerPublicKeyX963.count == 65 else {
            return nil
        }
        do {
            let decoded = try HawkRoutingBrokerKeyAuthorization.parse(
                authorization
            )
            guard decoded.expiresAtUnixSeconds > nowUnixSeconds,
                  constantTimeEqual(
                      decoded.brokerPublicKeyDigest,
                      Data(SHA256.hash(data: brokerPublicKeyX963))
                  ) else {
                return nil
            }
            if decoded.issuedAtUnixSeconds > nowUnixSeconds,
               decoded.issuedAtUnixSeconds - nowUnixSeconds
                   > HawkRoutingBrokerKeyAuthorization.maximumFutureSkewSeconds {
                return nil
            }
            let trustRoot = try P256.Signing.PublicKey(
                x963Representation: trustRootPublicKeyX963
            )
            let signature = try P256.Signing.ECDSASignature(
                derRepresentation: signatureDER
            )
            guard trustRoot.isValidSignature(signature, for: authorization) else {
                return nil
            }
            return decoded
        } catch {
            return nil
        }
    }

    private static func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for (leftByte, rightByte) in zip(left, right) {
            difference |= leftByte ^ rightByte
        }
        return difference == 0
    }
}

struct HawkRoutingReadinessReceipt {
    static let maximumLifetimeSeconds: UInt64 = 900
    static let maximumFutureSkewSeconds: UInt64 = 60

    private static let magic = Data("HAWKRR01".utf8)
    private static let version: UInt32 = 1
    private static let wireSize = 84

    let issuedAtUnixSeconds: UInt64
    let expiresAtUnixSeconds: UInt64
    let policyEpoch: UInt64
    let scopeDigest: Data
    let nonce: Data

    init(
        issuedAtUnixSeconds: UInt64,
        expiresAtUnixSeconds: UInt64,
        policyEpoch: UInt64,
        scopeDigest: Data,
        nonce: Data
    ) throws {
        guard issuedAtUnixSeconds > 0,
              expiresAtUnixSeconds > issuedAtUnixSeconds,
              expiresAtUnixSeconds - issuedAtUnixSeconds <= Self.maximumLifetimeSeconds else {
            throw HawkRoutingReceiptError.invalidLifetime
        }
        guard policyEpoch > 0 else {
            throw HawkRoutingReceiptError.invalidPolicyEpoch
        }
        guard scopeDigest.count == SHA256.byteCount else {
            throw HawkRoutingReceiptError.invalidScopeDigest
        }
        guard nonce.count == 16,
              nonce.contains(where: { $0 != 0 }) else {
            throw HawkRoutingReceiptError.invalidNonce
        }

        self.issuedAtUnixSeconds = issuedAtUnixSeconds
        self.expiresAtUnixSeconds = expiresAtUnixSeconds
        self.policyEpoch = policyEpoch
        self.scopeDigest = scopeDigest
        self.nonce = nonce
    }

    func serialized() throws -> Data {
        var wire = Self.magic
        wire.appendUInt32(Self.version)
        wire.appendUInt64(issuedAtUnixSeconds)
        wire.appendUInt64(expiresAtUnixSeconds)
        wire.appendUInt64(policyEpoch)
        wire.append(scopeDigest)
        wire.append(nonce)
        guard wire.count == Self.wireSize else {
            throw HawkRoutingReceiptError.invalidWireRepresentation
        }
        return wire
    }

    static func parse(_ wire: Data) throws -> Self {
        guard wire.count == wireSize,
              wire.prefix(magic.count) == magic,
              wire.readUInt32(at: 8) == version else {
            throw HawkRoutingReceiptError.invalidWireRepresentation
        }
        let issuedAt = wire.readUInt64(at: 12)
        let expiresAt = wire.readUInt64(at: 20)
        let epoch = wire.readUInt64(at: 28)
        let digest = wire.subdata(in: 36..<68)
        let nonce = wire.subdata(in: 68..<84)
        return try Self(
            issuedAtUnixSeconds: issuedAt,
            expiresAtUnixSeconds: expiresAt,
            policyEpoch: epoch,
            scopeDigest: digest,
            nonce: nonce
        )
    }
}

enum HawkRoutingReceiptVerifier {
    static func verify(
        receipt: Data,
        signatureDER: Data,
        publicKeyX963: Data,
        scope: HawkManagedRoutingScopeMaterial,
        nowUnixSeconds: UInt64
    ) -> Bool {
        verifiedReceipt(
            receipt: receipt,
            signatureDER: signatureDER,
            publicKeyX963: publicKeyX963,
            scope: scope,
            nowUnixSeconds: nowUnixSeconds
        ) != nil
    }

    static func verifiedReceipt(
        receipt: Data,
        signatureDER: Data,
        publicKeyX963: Data,
        scope: HawkManagedRoutingScopeMaterial,
        nowUnixSeconds: UInt64
    ) -> HawkRoutingReadinessReceipt? {
        guard receipt.count == 84,
              signatureDER.count >= 64,
              signatureDER.count <= 80,
              publicKeyX963.count == 65 else {
            return nil
        }

        do {
            let decoded = try HawkRoutingReadinessReceipt.parse(receipt)
            guard decoded.policyEpoch == scope.policyEpoch,
                  constantTimeEqual(decoded.scopeDigest, scope.canonicalDigest()),
                  decoded.expiresAtUnixSeconds > nowUnixSeconds else {
                return nil
            }
            if decoded.issuedAtUnixSeconds > nowUnixSeconds,
               decoded.issuedAtUnixSeconds - nowUnixSeconds
                   > HawkRoutingReadinessReceipt.maximumFutureSkewSeconds {
                return nil
            }

            let publicKey = try P256.Signing.PublicKey(
                x963Representation: publicKeyX963
            )
            let signature = try P256.Signing.ECDSASignature(
                derRepresentation: signatureDER
            )
            guard publicKey.isValidSignature(signature, for: receipt) else {
                return nil
            }
            return decoded
        } catch {
            return nil
        }
    }

    private static func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for (leftByte, rightByte) in zip(left, right) {
            difference |= leftByte ^ rightByte
        }
        return difference == 0
    }

}

private extension Data {
    mutating func appendUInt32(_ value: UInt32) {
        var encoded = value.bigEndian
        Swift.withUnsafeBytes(of: &encoded) { append(contentsOf: $0) }
    }

    mutating func appendUInt64(_ value: UInt64) {
        var encoded = value.bigEndian
        Swift.withUnsafeBytes(of: &encoded) { append(contentsOf: $0) }
    }

    mutating func appendLengthPrefixedASCII(_ value: String) {
        let bytes = Data(value.utf8)
        appendUInt32(UInt32(bytes.count))
        append(bytes)
    }

    func readUInt32(at offset: Int) -> UInt32 {
        var value: UInt32 = 0
        for index in offset..<(offset + 4) {
            value = (value << 8) | UInt32(self[index])
        }
        return value
    }

    func readUInt64(at offset: Int) -> UInt64 {
        var value: UInt64 = 0
        for index in offset..<(offset + 8) {
            value = (value << 8) | UInt64(self[index])
        }
        return value
    }
}
