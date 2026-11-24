import CryptoKit
import Foundation
import CoreFoundation

struct HawkManagedApplyRequest {
    let configuration: HawkManagedConfiguration

    static func parse(_ data: Data, command: String, anchor: [String: Any],
                      trustRoot: Data, now: UInt64) throws -> Self {
        let expectedMode: String
        switch command {
        case "apply-managed-monitor-policy": expectedMode = "monitor"
        case "apply-managed-enforce-policy": expectedMode = "enforce"
        default: throw HawkManagedRoutingAuthority.failure()
        }
        guard !data.isEmpty, data.count <= 2_500_000, data.starts(with: Data("bplist00".utf8)),
              let request = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              Set(request.keys) == Set(["schema", "version", "expected_policy_sha256", "managed_configuration_data", "routing_provider_configuration"]),
              request["schema"] as? String == "hawk.macos-managed-apply-request",
              HawkManagedRoutingAuthority.integer(request["version"]) == 1,
              let expectedDigest = request["expected_policy_sha256"] as? String,
              let configData = request["managed_configuration_data"] as? Data,
              let provider = request["routing_provider_configuration"] as? [String: Any] else {
            throw HawkManagedRoutingAuthority.failure()
        }
        var configuration = try HawkManagedConfiguration.parse(configData, routing: provider)
        guard configuration.mode == expectedMode,
              HawkManagedRoutingAuthority.digest(configuration.policyEnvelope) == expectedDigest else {
            throw HawkManagedRoutingAuthority.failure()
        }
        try HawkManagedRoutingAuthority.validate(configuration, provider: provider,
            anchor: anchor, trustRoot: trustRoot, now: now)
        configuration.trustedAnchor = anchor
        configuration.trustedRoot = trustRoot
        return Self(configuration: configuration)
    }

    static func read(command: String) throws -> Self {
        var input = Data()
        while true {
            let chunk = try FileHandle.standardInput.read(upToCount: min(65536, 2_500_001 - input.count)) ?? Data()
            if chunk.isEmpty { break }
            input.append(chunk)
            guard input.count <= 2_500_000 else { throw HawkManagedRoutingAuthority.failure() }
        }
        return try parse(input, command: command,
            anchor: HawkManagedRoutingAuthority.loadTrustAnchor(),
            trustRoot: HawkManagedRoutingAuthority.embeddedTrustRoot(),
            now: UInt64(Date().timeIntervalSince1970))
    }
}
