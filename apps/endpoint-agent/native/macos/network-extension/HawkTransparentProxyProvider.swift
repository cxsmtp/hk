import Foundation
import Network
import NetworkExtension

private enum ConfigurationError: Error {
    case managedRoutingDisabled
    case runtimeReadinessReceiptMissing
    case runtimeReadinessReceiptInvalid
    case functionalRelayDisabled
    case emptyApplicationScope
    case emptyDestinationScope
    case invalidPolicyEpoch
    case semanticInspectionRequirementMissing
    case semanticInspectionUnavailable
    case brokerKeyAuthorizationMissing
    case brokerKeyAuthorizationInvalid
    case routingTrustRootMissing
}

private struct ManagedRoutingScope {
    let applicationSigningIdentifiers: Set<String>
    let destinationHostSuffixes: Set<String>
    let policyEpoch: UInt64
    let semanticInspectionRequired: Bool
    let expiresAtUnixSeconds: UInt64
    let authorizationNonce: Data

    init(providerConfiguration: [String: Any]) throws {
        guard providerConfiguration["managedRoutingEnabled"] as? Bool == true else {
            throw ConfigurationError.managedRoutingDisabled
        }
        guard providerConfiguration["functionalRelayEnabled"] as? Bool == true else {
            throw ConfigurationError.functionalRelayDisabled
        }
        let applications = providerConfiguration["sourceAppSigningIdentifiers"] as? [String] ?? []
        let destinations = providerConfiguration["destinationHostSuffixes"] as? [String] ?? []
        guard !applications.isEmpty else {
            throw ConfigurationError.emptyApplicationScope
        }
        guard !destinations.isEmpty else {
            throw ConfigurationError.emptyDestinationScope
        }
        guard let policyEpoch = Self.unsignedInteger(
            providerConfiguration["policyEpoch"]
        ), policyEpoch > 0 else {
            throw ConfigurationError.invalidPolicyEpoch
        }
        guard let semanticInspectionRequired =
            providerConfiguration["semanticInspectionRequired"] as? Bool else {
            throw ConfigurationError.semanticInspectionRequirementMissing
        }
        guard !semanticInspectionRequired else {
            // This provider is a bounded transport relay. It must never turn a
            // semantic-inspection requirement into an uninspected direct flow.
            throw ConfigurationError.semanticInspectionUnavailable
        }
        guard let receipt = Self.configurationData(
            providerConfiguration["HawkRoutingReceipt"]
        ),
        let signature = Self.configurationData(
            providerConfiguration["HawkRoutingReceiptSignatureDER"]
        ),
        let publicKey = Self.configurationData(
            providerConfiguration["HawkRoutingReceiptPublicKeyX963"]
        ),
        let brokerKeyAuthorization = Self.configurationData(
            providerConfiguration["HawkRoutingBrokerKeyAuthorization"]
        ),
        let brokerKeyAuthorizationSignature = Self.configurationData(
            providerConfiguration["HawkRoutingBrokerKeyAuthorizationSignatureDER"]
        ) else {
            throw ConfigurationError.runtimeReadinessReceiptMissing
        }
        guard let encodedTrustRoot = Bundle.main.object(
            forInfoDictionaryKey: "HawkRoutingTrustRootPublicKeyX963Base64"
        ) as? String,
        encodedTrustRoot.utf8.count <= 1024,
        let trustRootPublicKey = Data(base64Encoded: encodedTrustRoot),
        trustRootPublicKey.count == 65 else {
            throw ConfigurationError.routingTrustRootMissing
        }

        let material: HawkManagedRoutingScopeMaterial
        do {
            material = try HawkManagedRoutingScopeMaterial(
                applicationSigningIdentifiers: applications,
                destinationHostSuffixes: destinations,
                policyEpoch: policyEpoch,
                semanticInspectionRequired: semanticInspectionRequired
            )
        } catch {
            throw ConfigurationError.runtimeReadinessReceiptInvalid
        }
        let currentTime = Date().timeIntervalSince1970
        guard currentTime >= 0 else {
            throw ConfigurationError.runtimeReadinessReceiptInvalid
        }
        let now = UInt64(currentTime)
        guard let verifiedAuthorization =
            HawkRoutingBrokerAuthorizationVerifier.verifiedAuthorization(
            authorization: brokerKeyAuthorization,
            signatureDER: brokerKeyAuthorizationSignature,
            trustRootPublicKeyX963: trustRootPublicKey,
            brokerPublicKeyX963: publicKey,
            nowUnixSeconds: now
        ) else {
            throw ConfigurationError.brokerKeyAuthorizationInvalid
        }
        guard let verifiedReceipt = HawkRoutingReceiptVerifier.verifiedReceipt(
                  receipt: receipt,
                  signatureDER: signature,
                  publicKeyX963: publicKey,
                  scope: material,
                  nowUnixSeconds: now
              ),
              verifiedReceipt.expiresAtUnixSeconds <=
                  verifiedAuthorization.expiresAtUnixSeconds else {
            throw ConfigurationError.runtimeReadinessReceiptInvalid
        }

        applicationSigningIdentifiers = Set(material.applicationSigningIdentifiers)
        destinationHostSuffixes = Set(material.destinationHostSuffixes)
        self.policyEpoch = material.policyEpoch
        self.semanticInspectionRequired = material.semanticInspectionRequired
        expiresAtUnixSeconds = verifiedReceipt.expiresAtUnixSeconds
        authorizationNonce = verifiedReceipt.nonce
    }

    private static func configurationData(_ value: Any?) -> Data? {
        if let data = value as? Data {
            return data
        }
        if let encoded = value as? String,
           encoded.utf8.count <= 4096 {
            return Data(base64Encoded: encoded)
        }
        return nil
    }

    private static func unsignedInteger(_ value: Any?) -> UInt64? {
        if let value = value as? UInt64 {
            return value
        }
        if let value = value as? Int, value > 0 {
            return UInt64(value)
        }
        if let value = value as? String,
           value.utf8.count <= 20 {
            return UInt64(value)
        }
        return nil
    }

    func contains(
        applicationSigningIdentifier: String?,
        destinationHost: String?,
        nowUnixSeconds: UInt64
    ) -> Bool {
        guard expiresAtUnixSeconds > nowUnixSeconds else { return false }
        guard let applicationSigningIdentifier,
              applicationSigningIdentifiers.contains(applicationSigningIdentifier),
              let destinationHost else {
            return false
        }
        guard let normalizedHost = try? HawkManagedRoutingScopeMaterial
            .normalizeDestinationSuffix(destinationHost) else {
            return false
        }
        return destinationHostSuffixes.contains { suffix in
            normalizedHost == suffix || normalizedHost.hasSuffix("." + suffix)
        }
    }
}

private protocol FlowRelay: AnyObject {
    func start()
    func cancel()
}

@available(macOS 15.0, *)
private final class TCPFlowRelay: FlowRelay {
    private static let maximumReadLength = 64 * 1024

    private let flow: NEAppProxyTCPFlow
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let onClose: () -> Void
    private let stateLock = NSLock()
    private var closed = false

    init(flow: NEAppProxyTCPFlow, remoteEndpoint: Network.NWEndpoint, onClose: @escaping () -> Void) {
        self.flow = flow
        connection = NWConnection(to: remoteEndpoint, using: .tcp)
        queue = DispatchQueue(label: "ai.hawk.endpoint.transparent-proxy.tcp")
        self.onClose = onClose
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.flow.open(withLocalFlowEndpoint: nil) { error in
                    guard error == nil else {
                        self.finish(error)
                        return
                    }
                    self.copyFlowToNetwork()
                    self.copyNetworkToFlow()
                }
            case let .failed(error):
                self.finish(error)
            case .cancelled:
                self.finish(nil)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    func cancel() {
        finish(nil)
    }

    private func copyFlowToNetwork() {
        flow.readData { [weak self] data, error in
            guard let self else { return }
            guard error == nil else {
                self.finish(error)
                return
            }
            guard let data, !data.isEmpty else {
                self.finish(nil)
                return
            }
            self.connection.send(content: data, completion: .contentProcessed { sendError in
                guard sendError == nil else {
                    self.finish(sendError)
                    return
                }
                self.copyFlowToNetwork()
            })
        }
    }

    private func copyNetworkToFlow() {
        connection.receive(
            minimumIncompleteLength: 1,
            maximumLength: 64 * 1024
        ) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            guard error == nil else {
                self.finish(error)
                return
            }
            if let data, !data.isEmpty {
                self.flow.write(data) { writeError in
                    guard writeError == nil else {
                        self.finish(writeError)
                        return
                    }
                    if isComplete {
                        self.finish(nil)
                    } else {
                        self.copyNetworkToFlow()
                    }
                }
            } else if isComplete {
                self.finish(nil)
            } else {
                self.copyNetworkToFlow()
            }
        }
    }

    private func finish(_ error: Error?) {
        stateLock.lock()
        guard !closed else {
            stateLock.unlock()
            return
        }
        closed = true
        stateLock.unlock()

        connection.stateUpdateHandler = nil
        connection.cancel()
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
        onClose()
    }
}

@available(macOS 15.0, *)
private final class UDPFlowRelay: FlowRelay {
    private let flow: NEAppProxyUDPFlow
    private let remoteEndpoint: Network.NWEndpoint
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let onClose: () -> Void
    private let stateLock = NSLock()
    private var closed = false

    init(
        flow: NEAppProxyUDPFlow,
        remoteEndpoint: Network.NWEndpoint,
        onClose: @escaping () -> Void
    ) {
        self.flow = flow
        self.remoteEndpoint = remoteEndpoint
        connection = NWConnection(to: remoteEndpoint, using: .udp)
        queue = DispatchQueue(label: "ai.hawk.endpoint.transparent-proxy.udp")
        self.onClose = onClose
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.flow.open(withLocalFlowEndpoint: nil) { error in
                    guard error == nil else {
                        self.finish(error)
                        return
                    }
                    self.copyFlowToNetwork()
                    self.copyNetworkToFlow()
                }
            case let .failed(error):
                self.finish(error)
            case .cancelled:
                self.finish(nil)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    func cancel() {
        finish(nil)
    }

    private func copyFlowToNetwork() {
        flow.readDatagrams { [weak self] packets, error in
            guard let self else { return }
            guard error == nil else {
                self.finish(error)
                return
            }
            guard let packets, !packets.isEmpty else {
                self.finish(nil)
                return
            }
            guard packets.allSatisfy({ $0.1 == self.remoteEndpoint }) else {
                self.finish(ConfigurationError.emptyDestinationScope)
                return
            }
            self.sendDatagrams(packets.map(\.0)[...])
        }
    }

    private func sendDatagrams(_ datagrams: ArraySlice<Data>) {
        guard let datagram = datagrams.first else {
            copyFlowToNetwork()
            return
        }
        connection.send(
            content: datagram,
            contentContext: .defaultMessage,
            isComplete: true,
            completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                guard error == nil else {
                    self.finish(error)
                    return
                }
                self.sendDatagrams(datagrams.dropFirst())
            }
        )
    }

    private func copyNetworkToFlow() {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            guard error == nil else {
                self.finish(error)
                return
            }
            guard let data, !data.isEmpty else {
                self.finish(nil)
                return
            }
            self.flow.writeDatagrams([(data, self.remoteEndpoint)]) { writeError in
                guard writeError == nil else {
                    self.finish(writeError)
                    return
                }
                self.copyNetworkToFlow()
            }
        }
    }

    private func finish(_ error: Error?) {
        stateLock.lock()
        guard !closed else {
            stateLock.unlock()
            return
        }
        closed = true
        stateLock.unlock()

        connection.stateUpdateHandler = nil
        connection.cancel()
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
        onClose()
    }
}

/// Explicitly scoped transparent proxy provider. Activation remains default-off
/// and depends on an externally validated readiness receipt in managed config.
@available(macOS 15.0, *)
final class HawkTransparentProxyProvider: NETransparentProxyProvider, NEAppProxyUDPFlowHandling {
    private let stateLock = NSLock()
    private let expiryQueue = DispatchQueue(
        label: "ai.hawk.endpoint.transparent-proxy.authorization-expiry"
    )
    private var relays: [ObjectIdentifier: FlowRelay] = [:]
    private var scope: ManagedRoutingScope?
    private var expiryTimer: DispatchSourceTimer?

    override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        do {
            guard let providerProtocol = protocolConfiguration as? NETunnelProviderProtocol,
                  let configuration = providerProtocol.providerConfiguration else {
                throw ConfigurationError.managedRoutingDisabled
            }
            let newScope = try ManagedRoutingScope(
                providerConfiguration: configuration
            )
            replaceRoutingAuthorization(with: newScope)
            completionHandler(nil)
        } catch {
            clearRoutingAuthorization()
            completionHandler(error)
        }
    }

    override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        clearRoutingAuthorization()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcpFlow = flow as? NEAppProxyTCPFlow,
              let scope = currentScope(),
              scope.contains(
                  applicationSigningIdentifier: flow.metaData.sourceAppSigningIdentifier,
                  destinationHost: destinationHost(for: tcpFlow.remoteFlowEndpoint),
                  nowUnixSeconds: currentUnixSeconds()
              ) else {
            return false
        }

        let identifier = ObjectIdentifier(flow)
        let relay = TCPFlowRelay(flow: tcpFlow, remoteEndpoint: tcpFlow.remoteFlowEndpoint) { [weak self] in
            self?.removeRelay(identifier)
        }
        guard storeRelay(
            relay,
            identifier: identifier,
            authorizationNonce: scope.authorizationNonce
        ) else {
            relay.cancel()
            return false
        }
        relay.start()
        return true
    }

    func handleNewUDPFlow(
        _ flow: NEAppProxyUDPFlow,
        initialRemoteFlowEndpoint remoteEndpoint: Network.NWEndpoint
    ) -> Bool {
        guard let scope = currentScope(),
              scope.contains(
                  applicationSigningIdentifier: flow.metaData.sourceAppSigningIdentifier,
                  destinationHost: destinationHost(for: remoteEndpoint),
                  nowUnixSeconds: currentUnixSeconds()
              ) else {
            return false
        }

        let identifier = ObjectIdentifier(flow)
        let relay = UDPFlowRelay(
            flow: flow,
            remoteEndpoint: remoteEndpoint
        ) { [weak self] in self?.removeRelay(identifier) }
        guard storeRelay(
            relay,
            identifier: identifier,
            authorizationNonce: scope.authorizationNonce
        ) else {
            relay.cancel()
            return false
        }
        relay.start()
        return true
    }

    private func storeRelay(
        _ relay: FlowRelay,
        identifier: ObjectIdentifier,
        authorizationNonce: Data
    ) -> Bool {
        stateLock.lock()
        guard let scope,
              scope.authorizationNonce == authorizationNonce,
              scope.expiresAtUnixSeconds > currentUnixSeconds() else {
            stateLock.unlock()
            return false
        }
        relays[identifier] = relay
        stateLock.unlock()
        return true
    }

    private func removeRelay(_ identifier: ObjectIdentifier) {
        stateLock.lock()
        relays.removeValue(forKey: identifier)
        stateLock.unlock()
    }

    private func currentScope() -> ManagedRoutingScope? {
        stateLock.lock()
        let activeScope = scope
        stateLock.unlock()
        return activeScope
    }

    private func replaceRoutingAuthorization(with newScope: ManagedRoutingScope) {
        clearRoutingAuthorization()
        stateLock.lock()
        scope = newScope
        stateLock.unlock()
        scheduleRoutingAuthorizationExpiry(for: newScope)
    }

    private func scheduleRoutingAuthorizationExpiry(
        for authorization: ManagedRoutingScope
    ) {
        let now = Date().timeIntervalSince1970
        let expiry = TimeInterval(authorization.expiresAtUnixSeconds)
        guard now >= 0, expiry > now else {
            expireRoutingAuthorization(
                nonce: authorization.authorizationNonce
            )
            return
        }
        let timer = DispatchSource.makeTimerSource(queue: expiryQueue)
        timer.schedule(deadline: .now() + (expiry - now))
        timer.setEventHandler { [weak self] in
            self?.expireRoutingAuthorization(
                nonce: authorization.authorizationNonce
            )
        }
        timer.resume()

        stateLock.lock()
        guard scope?.authorizationNonce == authorization.authorizationNonce else {
            stateLock.unlock()
            timer.cancel()
            return
        }
        let priorTimer = expiryTimer
        expiryTimer = timer
        stateLock.unlock()
        priorTimer?.cancel()
    }

    private func expireRoutingAuthorization(nonce: Data) {
        stateLock.lock()
        guard scope?.authorizationNonce == nonce else {
            stateLock.unlock()
            return
        }
        scope = nil
        let activeRelays = Array(relays.values)
        relays.removeAll()
        let timer = expiryTimer
        expiryTimer = nil
        stateLock.unlock()

        timer?.cancel()
        activeRelays.forEach { $0.cancel() }
    }

    private func clearRoutingAuthorization() {
        stateLock.lock()
        scope = nil
        let activeRelays = Array(relays.values)
        relays.removeAll()
        let timer = expiryTimer
        expiryTimer = nil
        stateLock.unlock()

        timer?.cancel()
        activeRelays.forEach { $0.cancel() }
    }

    private func currentUnixSeconds() -> UInt64 {
        let timestamp = Date().timeIntervalSince1970
        return timestamp > 0 ? UInt64(timestamp) : 0
    }

    private func destinationHost(for endpoint: Network.NWEndpoint) -> String? {
        guard case let .hostPort(host, _) = endpoint else { return nil }
        return String(describing: host)
    }
}
