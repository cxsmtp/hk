import CryptoKit
import Foundation

@objc private protocol HawkEndpointPolicyDelivery {
    func installPolicyEnvelope(_ envelope: Data,
                               reply: @escaping (Bool, Int) -> Void)
    func copyPolicyHealth(withReply reply: @escaping ([String: Any]) -> Void)
}

final class HawkEndpointPolicyClient {
    private func failure(_ code: Int) -> NSError {
        NSError(domain: "ai.hawk.endpoint.policy", code: code)
    }

    private func hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func withConnection<T>(
        _ configuration: HawkManagedConfiguration,
        _ operation: (HawkEndpointPolicyDelivery, NSXPCConnection) throws -> T
    ) throws -> T {
        let expectedService = "\(configuration.teamIdentifier).ai.hawk.endpoint.endpoint-security.policy"
        guard Bundle.main.bundleIdentifier == HawkManagedConfiguration.hostBundleIdentifier,
              let serviceName = Bundle.main.object(forInfoDictionaryKey:
                "HawkEndpointPolicyMachServiceName") as? String,
              serviceName == expectedService else { throw failure(5) }
        let connection = NSXPCConnection(machServiceName: serviceName, options: [])
        connection.setCodeSigningRequirement(
            "anchor apple generic and identifier \"ai.hawk.endpoint.endpoint-security\" and certificate leaf[subject.OU] = \"\(configuration.teamIdentifier)\""
        )
        connection.remoteObjectInterface = NSXPCInterface(with: HawkEndpointPolicyDelivery.self)
        connection.resume()
        defer { connection.invalidate() }
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in })
                as? HawkEndpointPolicyDelivery else { throw failure(1) }
        return try operation(proxy, connection)
    }

    private func install(_ configuration: HawkManagedConfiguration) throws {
        try withConnection(configuration) { proxy, _ in
            let semaphore = DispatchSemaphore(value: 0)
            var accepted = false
            proxy.installPolicyEnvelope(configuration.policyEnvelope) { installed, _ in
                accepted = installed
                semaphore.signal()
            }
            guard semaphore.wait(timeout: .now() + 5) == .success, accepted else {
                throw failure(2)
            }
        }
    }

    private func readHealth(_ configuration: HawkManagedConfiguration) throws -> [String: Any] {
        try withConnection(configuration) { proxy, _ in
            let semaphore = DispatchSemaphore(value: 0)
            var health: [String: Any]?
            proxy.copyPolicyHealth { received in
                health = received
                semaphore.signal()
            }
            guard semaphore.wait(timeout: .now() + 5) == .success,
                  let health, health.count <= 32 else { throw failure(3) }
            return health
        }
    }

    func status(_ configuration: HawkManagedConfiguration) throws -> [String: Any] {
        let health = try readHealth(configuration)
        guard health["schema_version"] as? Int == 1,
              health["bundle_id"] as? String == HawkManagedConfiguration.endpointSecurityBundleIdentifier,
              health["team_id"] as? String == configuration.teamIdentifier,
              health["policy_digest"] as? String == hex(configuration.policyEnvelope),
              health["signing_key_digest"] as? String == hex(configuration.signingKey),
              (health["policy_epoch"] as? NSNumber)?.uint64Value == configuration.policyEpoch,
              ((health["delivery_sequence"] as? NSNumber)?.uint64Value ?? 0) > 0,
              let lineageOccupancy = (health["lineage_occupancy"] as? NSNumber)?.uint64Value,
              lineageOccupancy <= 512,
              let lineageFailures = (health["lineage_record_failure_count"] as? NSNumber)?.uint64Value,
              health["policy_version"] as? String == configuration.policyVersion,
              (health["issued_at_unix_seconds"] as? NSNumber)?.uint64Value == configuration.issuedAtUnixSeconds,
              (health["expires_at_unix_seconds"] as? NSNumber)?.uint64Value == configuration.expiresAtUnixSeconds,
              let actualMode = health["mode"] as? Int,
              actualMode == (configuration.mode == "enforce" ? 2 : 1) else {
            throw failure(4)
        }
        let now = UInt64(Date().timeIntervalSince1970)
        let current = configuration.issuedAtUnixSeconds <= now + 60 &&
            now < configuration.expiresAtUnixSeconds &&
            health["policy_current"] as? Bool == true
        let endpointHealthy = current && health["active"] as? Bool == true &&
            health["signature_verified"] as? Bool == true &&
            health["signer_pin_verified"] as? Bool == true &&
            health["configuration_integrity_valid"] as? Bool == true &&
            lineageFailures == 0
        let managers = try configuration.networkManagerStatus()
        let networkHealthy = managers.filterEnabled && managers.routingEnabled
        var reasons: [String] = []
        if !endpointHealthy { reasons.append("endpoint_policy_unhealthy") }
        if lineageFailures > 0 { reasons.append("process_lineage_overflow") }
        if !managers.filterEnabled { reasons.append("content_filter_inactive") }
        if !managers.routingEnabled { reasons.append("routing_extension_inactive") }
        // Child attribution and target acceptance require signed-device proof.
        reasons.append("network_child_attribution_unverified")
        reasons.append("target_acceptance_unverified")
        return [
            "schema": "hawk.macos-native-status",
            "mode": configuration.mode,
            "policy_signed": health["signature_verified"] as? Bool == true,
            "policy_current": current,
            "policy_digest": hex(configuration.policyEnvelope),
            "policy_epoch": configuration.policyEpoch,
            "policy_version": configuration.policyVersion,
            "issued_at_unix_seconds": configuration.issuedAtUnixSeconds,
            "expires_at_unix_seconds": configuration.expiresAtUnixSeconds,
            "host_bundle_id": HawkManagedConfiguration.hostBundleIdentifier,
            "endpoint_security_bundle_id": HawkManagedConfiguration.endpointSecurityBundleIdentifier,
            "content_filter_bundle_id": HawkManagedConfiguration.contentFilterBundleIdentifier,
            "routing_bundle_id": HawkManagedConfiguration.routingBundleIdentifier,
            "team_id": configuration.teamIdentifier,
            "file_control": endpointHealthy ? "verified" : "unknown",
            "process_control": endpointHealthy ? "verified" : "unknown",
            "network_control": networkHealthy ? "active_unverified" : "unknown",
            "network_child_attribution_verified": false,
            "target_acceptance": false,
            "healthy": endpointHealthy && networkHealthy,
            "reason_codes": reasons,
        ]
    }

    func apply(_ configuration: HawkManagedConfiguration) throws -> [String: Any] {
        // Routing renewal must not replay an already-installed native delivery
        // sequence. status binds the exact digest, key, epoch, mode and times.
        let existing = try? status(configuration)
        if existing?["policy_current"] as? Bool != true || existing?["policy_signed"] as? Bool != true {
            try install(configuration)
        }
        _ = try configuration.configureNetworkManagers()
        return try status(configuration)
    }
}
