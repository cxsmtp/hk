import Darwin
import Foundation
import NetworkExtension

struct HawkManagedConfiguration {
    static let hostBundleIdentifier = "ai.hawk.endpoint.host"
    static let endpointSecurityBundleIdentifier = "ai.hawk.endpoint.endpoint-security"
    static let contentFilterBundleIdentifier = "ai.hawk.endpoint.content-filter"
    static let routingBundleIdentifier = "ai.hawk.endpoint.managed-routing"

    let policyEnvelope: Data
    let signingKey: Data
    let teamIdentifier: String
    let policyEpoch: UInt64
    let policyVersion: String
    let mode: String
    let issuedAtUnixSeconds: UInt64
    let expiresAtUnixSeconds: UInt64
    let routingConfiguration: [String: Any]
    let rawConfiguration: [String: Any]
    var trustedAnchor: [String: Any]? = nil
    var trustedRoot: Data? = nil

    private static func failure(_ code: Int) -> NSError {
        NSError(domain: "ai.hawk.endpoint.managed-config", code: code)
    }

    static func load(from path: URL) throws -> HawkManagedConfiguration {
        guard path.path == "/Library/Managed Preferences/ai.hawk.endpoint.host.plist" else {
            throw failure(1)
        }
        let descriptor = Darwin.open(path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw failure(2) }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        var metadata = Darwin.stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_uid == 0,
              (metadata.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              metadata.st_mode & 0o022 == 0,
              metadata.st_size > 0,
              metadata.st_size <= 2_200_000 else { throw failure(3) }
        let data = try handle.readToEnd() ?? Data()
        guard data.count == Int(metadata.st_size) else { throw failure(4) }
        return try parse(data)
    }

    static func parse(_ data: Data, routing: [String: Any] = [:]) throws -> HawkManagedConfiguration {
        let allowed: Set<String> = [
            "HawkPolicyEnvelope", "HawkPolicySigningPublicKeyX963", "HawkTeamIdentifier",
            "HawkHostBundleIdentifier", "HawkEndpointSecurityBundleIdentifier", "HawkContentFilterBundleIdentifier", "HawkRoutingBundleIdentifier",
            "HawkPolicyEpoch", "HawkPolicyVersion", "HawkPolicyMode", "HawkPolicyIssuedAtUnixSeconds", "HawkPolicyExpiresAtUnixSeconds",
            "HawkSourcePolicyEnvelopeJSON", "HawkNativeBindingEnvelopeJSON", "HawkRoutingScopeEnvelopeJSON",
            "HawkRoutingReceiptPublicKeyX963", "HawkRoutingBrokerKeyAuthorization", "HawkRoutingBrokerKeyAuthorizationSignatureDER", "HawkRoutingTrustRootPublicKeyX963",
        ]
        guard !data.isEmpty, data.count <= 2_200_000,
              let plist = try PropertyListSerialization.propertyList(
                from: data, options: [], format: nil
              ) as? [String: Any],
              Set(plist.keys) == allowed,
              let envelope = plist["HawkPolicyEnvelope"] as? Data,
              let key = plist["HawkPolicySigningPublicKeyX963"] as? Data,
              envelope.count > 0, envelope.count <= 2 * 1024 * 1024,
              key.count == 65, key.first == 0x04,
              plist["HawkHostBundleIdentifier"] as? String == hostBundleIdentifier,
              plist["HawkEndpointSecurityBundleIdentifier"] as? String == endpointSecurityBundleIdentifier,
              plist["HawkContentFilterBundleIdentifier"] as? String == contentFilterBundleIdentifier,
              plist["HawkRoutingBundleIdentifier"] as? String == routingBundleIdentifier,
              let team = plist["HawkTeamIdentifier"] as? String,
              team.count == 10,
              team.utf8.allSatisfy({ ($0 >= 65 && $0 <= 90) || ($0 >= 48 && $0 <= 57) }),
              let epoch = plist["HawkPolicyEpoch"] as? NSNumber,
              epoch.uint64Value > 0,
              let version = plist["HawkPolicyVersion"] as? String,
              !version.isEmpty, version.utf8.count < 64,
              let mode = plist["HawkPolicyMode"] as? String,
              mode == "monitor" || mode == "enforce",
              let issued = plist["HawkPolicyIssuedAtUnixSeconds"] as? NSNumber,
              let expires = plist["HawkPolicyExpiresAtUnixSeconds"] as? NSNumber,
              issued.uint64Value < expires.uint64Value
        else { throw failure(4) }
        return HawkManagedConfiguration(
            policyEnvelope: envelope, signingKey: key,
            teamIdentifier: team, policyEpoch: epoch.uint64Value,
            policyVersion: version, mode: mode,
            issuedAtUnixSeconds: issued.uint64Value,
            expiresAtUnixSeconds: expires.uint64Value,
            routingConfiguration: routing, rawConfiguration: plist
        )
    }

    private func waitFor(_ start: (@escaping (Error?) -> Void) -> Void) throws {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Error?
        start { error in result = error; semaphore.signal() }
        guard semaphore.wait(timeout: .now() + 5) == .success else {
            throw Self.failure(5)
        }
        if let result { throw result }
    }

    private func routingManager() throws -> NETransparentProxyManager {
        let semaphore = DispatchSemaphore(value: 0)
        var managers: [NETransparentProxyManager]?
        var result: Error?
        NETransparentProxyManager.loadAllFromPreferences { loaded, error in
            managers = loaded
            result = error
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + 5) == .success else {
            throw Self.failure(6)
        }
        if let result { throw result }
        let matches = (managers ?? []).filter {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier ==
                Self.routingBundleIdentifier
        }
        guard matches.count <= 1 else { throw Self.failure(7) }
        return matches.first ?? NETransparentProxyManager()
    }

    func networkManagerStatus() throws -> (filterEnabled: Bool, routingEnabled: Bool) {
        let filter = NEFilterManager.shared()
        try waitFor { filter.loadFromPreferences(completionHandler: $0) }
        let routing = try routingManager()
        guard let provider = (routing.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration else {
            return (filter.isEnabled, false)
        }
        do {
            try HawkManagedRoutingAuthority.validate(self, provider: provider,
                anchor: trustedAnchor ?? HawkManagedRoutingAuthority.loadTrustAnchor(),
                trustRoot: trustedRoot ?? HawkManagedRoutingAuthority.embeddedTrustRoot(),
                now: UInt64(Date().timeIntervalSince1970))
        } catch { return (filter.isEnabled, false) }
        return (filter.isEnabled, routing.isEnabled)
    }

    func configureNetworkManagers() throws -> (filterEnabled: Bool, routingEnabled: Bool) {
        let filter = NEFilterManager.shared()
        try waitFor { filter.loadFromPreferences(completionHandler: $0) }
        let filterWasEnabled = filter.isEnabled
        let provider = NEFilterProviderConfiguration()
        provider.filterSockets = true
        provider.vendorConfiguration = [
            "HawkPolicyEnvelope": policyEnvelope,
            "HawkPolicySigningPublicKeyX963": signingKey,
        ]
        filter.providerConfiguration = provider
        filter.localizedDescription = "Hawk Endpoint"
        filter.isEnabled = filterWasEnabled
        try waitFor { filter.saveToPreferences(completionHandler: $0) }

        let routing = try routingManager()
        let routingWasEnabled = routing.isEnabled
        let protocolConfiguration = NETunnelProviderProtocol()
        protocolConfiguration.providerBundleIdentifier = Self.routingBundleIdentifier
        protocolConfiguration.serverAddress = "Hawk Endpoint"
        protocolConfiguration.providerConfiguration = routingConfiguration
        routing.protocolConfiguration = protocolConfiguration
        routing.localizedDescription = "Hawk Managed Routing"
        routing.isEnabled = routingWasEnabled
        try waitFor { routing.saveToPreferences(completionHandler: $0) }
        return try networkManagerStatus()
    }
}
