import CryptoKit
import Darwin
import Foundation
import CoreFoundation

enum HawkManagedRoutingAuthority {
    static func failure() -> NSError { NSError(domain: "ai.hawk.endpoint.routing-authority", code: 1) }
    static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func integer(_ value: Any?) -> UInt64? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue >= 0, number.stringValue.range(of: "^[0-9]+$", options: .regularExpression) != nil else { return nil }
        return UInt64(number.stringValue)
    }
    static func boolean(_ value: Any?, equals expected: Bool) -> Bool {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return false }
        return number.boolValue == expected
    }
    static func canonical(_ value: Any) throws -> Data {
        let encoded = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
        guard let text = String(data: encoded, encoding: .utf8) else { throw failure() }
        var ascii = ""
        for scalar in text.unicodeScalars {
            if scalar.value < 128 { ascii.unicodeScalars.append(scalar) }
            else if scalar.value <= 0xffff { ascii += String(format: "\\u%04x", scalar.value) }
            else {
                let value = scalar.value - 0x10000
                ascii += String(format: "\\u%04x\\u%04x", 0xd800 + (value >> 10), 0xdc00 + (value & 1023))
            }
        }
        return Data(ascii.utf8)
    }
    static func loadTrustAnchor() throws -> [String: Any] {
        let path = "/Library/Application Support/Hawk/EndpointAgent/endpoint-agent.json"
        let descriptor = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw failure() }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        var before = Darwin.stat()
        guard fstat(descriptor, &before) == 0, before.st_uid == 0,
              before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), before.st_mode & 0o022 == 0,
              before.st_size > 0, before.st_size <= 262144 else { throw failure() }
        let data = try handle.read(upToCount: 262145) ?? Data()
        var after = Darwin.stat()
        guard data.count == Int(before.st_size), lstat(path, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              let anchor = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw failure() }
        return anchor
    }
    static func embeddedTrustRoot() throws -> Data {
        let extensionURL = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/HawkManagedRoutingExtension.systemextension")
        guard let bundle = Bundle(url: extensionURL), bundle.bundleIdentifier == HawkManagedConfiguration.routingBundleIdentifier,
              let encoded = bundle.object(forInfoDictionaryKey: "HawkRoutingTrustRootPublicKeyX963Base64") as? String,
              let root = Data(base64Encoded: encoded), root.count == 65 else { throw failure() }
        return root
    }
    private static func object(_ data: Any?) throws -> [String: Any] {
        guard let data = data as? Data, !data.isEmpty, data.count <= 2_200_000,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw failure() }
        return value
    }
    private static func signature(_ object: [String: Any], key: Curve25519.Signing.PublicKey, data: Data) throws {
        guard object["algorithm"] as? String == "Ed25519", let encoded = object["signature"] as? String,
              let signed = Data(base64Encoded: encoded), signed.count == 64,
              key.isValidSignature(signed, for: data) else { throw failure() }
    }
    private static func seconds(_ value: Any?) throws -> UInt64 {
        guard let text = value as? String, text.range(of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", options: .regularExpression) != nil,
              let date = ISO8601DateFormatter().date(from: text), date.timeIntervalSince1970 > 0 else { throw failure() }
        return UInt64(date.timeIntervalSince1970)
    }
    private static func little(_ data: Data, _ offset: Int, _ count: Int) throws -> UInt64 {
        guard offset >= 0, offset + count <= data.count else { throw failure() }
        return data[offset..<(offset + count)].enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << ($1.offset * 8) }
    }
    static func validate(_ config: HawkManagedConfiguration, provider: [String: Any],
                         anchor: [String: Any], trustRoot: Data, now: UInt64) throws {
        let raw = config.rawConfiguration
        let envelope = try object(raw["HawkRoutingScopeEnvelopeJSON"])
        guard Set(envelope.keys) == Set(["schema", "version", "key_id", "algorithm", "payload", "signature"]),
              envelope["schema"] as? String == "hawk.macos-routing-scope-envelope", integer(envelope["version"]) == 1,
              let keyID = envelope["key_id"] as? String,
              anchor["security_profile"] as? String == "bank", anchor["deployment_mode"] as? String == "managed_machine",
              boolean(anchor["macos_native_enforcement_enabled"], equals: true),
              let keys = anchor["endpoint_floor_policy_public_keys"] as? [String: String], !keys.isEmpty, keys.count <= 32,
              keys.keys.allSatisfy({ $0.range(of: "^[A-Za-z0-9._:-]{1,128}$", options: .regularExpression) != nil }),
              let encodedKey = keys[keyID], let publicBytes = Data(base64Encoded: encodedKey), publicBytes.count == 32,
              let encoded = envelope["payload"] as? String, encoded.utf8.count <= 262144,
              let payload = Data(base64Encoded: encoded),
              let scope = try JSONSerialization.jsonObject(with: payload) as? [String: Any],
              Set(scope.keys) == Set(["schema", "version", "source_policy_sha256", "native_policy_sha256", "tenant_id", "device_id", "policy_version", "policy_epoch", "delivery_sequence", "mode", "issued_at", "expires_at", "routing_transport", "application_signing_identifiers", "destination_host_suffixes", "semantic_inspection_required"]),
              scope["schema"] as? String == "hawk.macos-routing-scope", integer(scope["version"]) == 1,
              scope["routing_transport"] as? String == "direct_transparent_relay", boolean(scope["semantic_inspection_required"], equals: false),
              let tenant = scope["tenant_id"] as? String, !tenant.isEmpty, tenant == anchor["tenant_id"] as? String,
              let device = scope["device_id"] as? String, !device.isEmpty, device == anchor["endpoint_id"] as? String,
              scope["native_policy_sha256"] as? String == digest(config.policyEnvelope),
              scope["mode"] as? String == config.mode, integer(scope["policy_epoch"]) == config.policyEpoch,
              scope["policy_version"] as? String == config.policyVersion,
              let applications = scope["application_signing_identifiers"] as? [String],
              let destinations = scope["destination_host_suffixes"] as? [String],
              !applications.isEmpty, applications.count <= 256, !destinations.isEmpty, destinations.count <= 256,
              applications == Set(applications).sorted(), destinations == Set(destinations).sorted(),
              trustRoot == raw["HawkRoutingTrustRootPublicKeyX963"] as? Data else { throw failure() }
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicBytes)
        guard try canonical(scope) == payload else { throw failure() }
        try signature(envelope, key: key, data: Data("hawk.macos-routing-scope.v1\0".utf8) + payload)
        let issued = try seconds(scope["issued_at"]), expires = try seconds(scope["expires_at"])
        guard issued == config.issuedAtUnixSeconds, expires == config.expiresAtUnixSeconds,
              issued <= now, now < expires, expires - issued <= 86400 else { throw failure() }
        let material = try HawkManagedRoutingScopeMaterial(applicationSigningIdentifiers: applications,
            destinationHostSuffixes: destinations, policyEpoch: config.policyEpoch, semanticInspectionRequired: false)
        guard material.applicationSigningIdentifiers == applications, material.destinationHostSuffixes == destinations,
              destinations.allSatisfy({ $0.range(of: "^[0-9.]+$", options: .regularExpression) == nil }) else { throw failure() }

        // Both original tenant-authority documents must name the same signer.
        let source = try object(raw["HawkSourcePolicyEnvelopeJSON"])
        let binding = try object(raw["HawkNativeBindingEnvelopeJSON"])
        guard Set(source.keys) == Set(["key_id", "algorithm", "policy", "signature"]),
              Set(binding.keys) == Set(["schema", "version", "key_id", "algorithm", "bindings", "signature"]),
              source["key_id"] as? String == keyID, binding["key_id"] as? String == keyID,
              binding["schema"] as? String == "hawk.macos-native-bindings-envelope", integer(binding["version"]) == 1,
              let policy = source["policy"] as? [String: Any], let bindings = binding["bindings"] as? [String: Any] else { throw failure() }
        let policyBytes = try canonical(policy)
        try signature(source, key: key, data: policyBytes)
        try signature(binding, key: key, data: Data("hawk.macos-native-bindings.v1\0".utf8) + canonical(bindings))
        guard scope["source_policy_sha256"] as? String == digest(policyBytes),
              bindings["source_policy_sha256"] as? String == digest(policyBytes) else { throw failure() }
        for field in ["tenant_id", "device_id", "policy_version", "policy_epoch", "issued_at", "expires_at"] {
            guard let value = scope[field], let a = policy[field], let b = bindings[field],
                  try canonical([value]) == canonical([a]), try canonical([value]) == canonical([b]) else { throw failure() }
        }
        guard bindings["mode"] as? String == config.mode, integer(bindings["delivery_sequence"]) == integer(scope["delivery_sequence"]),
              let rules = policy["rules"] as? [[String: Any]], let identities = bindings["identities"] as? [[String: Any]] else { throw failure() }
        var used = Set<String>()
        for rule in rules {
            guard let match = rule["match"] as? [String: Any], let primitives = match["primitives"] as? [String] else { throw failure() }
            if !Set(primitives).isDisjoint(with: ["network_connect", "network_quic", "network_localhost"]) {
                guard let binaries = match["binary_identities"] as? [String], !binaries.isEmpty else { throw failure() }
                used.formUnion(binaries)
            }
        }
        var mapped = Set<String>(), names = Set<String>()
        for identity in identities {
            guard let original = identity["source_identity"] as? String, let signing = identity["signing_id"] as? String else { throw failure() }
            if used.contains(original) { mapped.insert(original); names.insert(signing) }
        }
        guard mapped == used, names.sorted() == applications else { throw failure() }

        let native = config.policyEnvelope
        let length = try little(native, 4, 4), signatureLength = try little(native, 8, 4)
        guard try little(native, 0, 4) == 2, try little(native, 12, 4) == 0,
              length >= 352, signatureLength >= 8, signatureLength <= 80,
              16 + length + signatureLength == native.count else { throw failure() }
        let nativePayload = native.subdata(in: 16..<(16 + Int(length)))
        let nativeSignature = try P256.Signing.ECDSASignature(derRepresentation: native.suffix(Int(signatureLength)))
        let nativeKey = try P256.Signing.PublicKey(x963Representation: config.signingKey)
        guard nativeKey.isValidSignature(nativeSignature, for: nativePayload),
              try little(nativePayload, 0, 4) == 2, try little(nativePayload, 4, 4) == 2,
              try little(nativePayload, 8, 8) == integer(scope["delivery_sequence"]),
              try little(nativePayload, 16, 8) == config.policyEpoch,
              try little(nativePayload, 24, 8) == issued, try little(nativePayload, 32, 8) == expires,
              try little(nativePayload, 60, 4) == (config.mode == "enforce" ? 2 : 1),
              nativePayload.subdata(in: 64..<96) == Data(SHA256.hash(data: Data(tenant.utf8))),
              nativePayload.subdata(in: 96..<128) == Data(SHA256.hash(data: Data(device.utf8))) else { throw failure() }
        try validateProvider(provider, material: material, raw: raw, trustRoot: trustRoot, issued: issued, expires: expires, now: now)
    }
    private static func validateProvider(_ provider: [String: Any], material: HawkManagedRoutingScopeMaterial,
                                        raw: [String: Any], trustRoot: Data, issued: UInt64, expires: UInt64, now: UInt64) throws {
        let binaryFields = ["HawkRoutingReceipt", "HawkRoutingReceiptSignatureDER", "HawkRoutingReceiptPublicKeyX963", "HawkRoutingBrokerKeyAuthorization", "HawkRoutingBrokerKeyAuthorizationSignatureDER"]
        guard Set(provider.keys) == Set(binaryFields + ["managedRoutingEnabled", "functionalRelayEnabled", "sourceAppSigningIdentifiers", "destinationHostSuffixes", "policyEpoch", "semanticInspectionRequired"]),
              boolean(provider["managedRoutingEnabled"], equals: true), boolean(provider["functionalRelayEnabled"], equals: true),
              boolean(provider["semanticInspectionRequired"], equals: false), integer(provider["policyEpoch"]) == material.policyEpoch,
              provider["sourceAppSigningIdentifiers"] as? [String] == material.applicationSigningIdentifiers,
              provider["destinationHostSuffixes"] as? [String] == material.destinationHostSuffixes else { throw failure() }
        var values = [String: Data]()
        for field in binaryFields {
            guard let text = provider[field] as? String, text.utf8.count <= 128, let value = Data(base64Encoded: text) else { throw failure() }
            values[field] = value
        }
        for field in ["HawkRoutingReceiptPublicKeyX963", "HawkRoutingBrokerKeyAuthorization", "HawkRoutingBrokerKeyAuthorizationSignatureDER"] {
            guard values[field] == raw[field] as? Data else { throw failure() }
        }
        guard let authorization = HawkRoutingBrokerAuthorizationVerifier.verifiedAuthorization(
            authorization: values["HawkRoutingBrokerKeyAuthorization"]!, signatureDER: values["HawkRoutingBrokerKeyAuthorizationSignatureDER"]!,
            trustRootPublicKeyX963: trustRoot, brokerPublicKeyX963: values["HawkRoutingReceiptPublicKeyX963"]!, nowUnixSeconds: now),
              let receipt = HawkRoutingReceiptVerifier.verifiedReceipt(receipt: values["HawkRoutingReceipt"]!,
                signatureDER: values["HawkRoutingReceiptSignatureDER"]!, publicKeyX963: values["HawkRoutingReceiptPublicKeyX963"]!, scope: material, nowUnixSeconds: now),
              receipt.issuedAtUnixSeconds >= issued, receipt.issuedAtUnixSeconds <= now,
              receipt.expiresAtUnixSeconds <= min(expires, authorization.expiresAtUnixSeconds),
              receipt.expiresAtUnixSeconds - receipt.issuedAtUnixSeconds <= 120 else { throw failure() }
    }
}
