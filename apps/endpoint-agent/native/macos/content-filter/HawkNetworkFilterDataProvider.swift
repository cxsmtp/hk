import Foundation
import Network
import NetworkExtension

private enum HawkNetworkAction {
    case allow
    case block
    case localEscalationRequired
}

struct HawkNetworkFlowContext {
    let sourceProcessAuditToken: Data
    let sourceApplicationAuditToken: Data
    let destinationHost: Data
    let destinationPort: UInt16
    let protocolNumber: Int32
    let socketFamily: Int32

    static func from(
        isSocketFlow: Bool,
        sourceProcessAuditToken: Data?,
        sourceApplicationAuditToken: Data?,
        endpoint: Network.NWEndpoint?,
        protocolNumber: Int32,
        socketFamily: Int32
    ) -> HawkNetworkFlowContext? {
        guard isSocketFlow,
              let sourceProcessAuditToken, !sourceProcessAuditToken.isEmpty,
              let sourceApplicationAuditToken, !sourceApplicationAuditToken.isEmpty,
              let endpoint,
              case let .hostPort(hostValue, portValue) = endpoint,
              let hostBytes = String(describing: hostValue).data(using: .utf8),
              !hostBytes.isEmpty,
              portValue.rawValue > 0 else { return nil }
        return HawkNetworkFlowContext(
            sourceProcessAuditToken: sourceProcessAuditToken,
            sourceApplicationAuditToken: sourceApplicationAuditToken,
            destinationHost: hostBytes,
            destinationPort: portValue.rawValue,
            protocolNumber: protocolNumber,
            socketFamily: socketFamily
        )
    }
}

@_silgen_name("HawkEvaluateNetworkFlow")
private func HawkEvaluateNetworkFlow(
    _ sourceProcessAuditToken: UnsafePointer<UInt8>?,
    _ sourceProcessAuditTokenLength: Int,
    _ sourceApplicationAuditToken: UnsafePointer<UInt8>?,
    _ sourceApplicationAuditTokenLength: Int,
    _ destinationHost: UnsafePointer<UInt8>?,
    _ destinationHostLength: Int,
    _ destinationPort: UInt16,
    _ protocolNumber: Int32,
    _ socketFamily: Int32
) -> Int32

@_silgen_name("HawkMacVerifyAndInstallPolicyEnvelope")
private func HawkMacVerifyAndInstallPolicyEnvelope(
    _ envelope: UnsafePointer<UInt8>?,
    _ envelopeLength: Int,
    _ pinnedPublicKeyX963: UnsafePointer<UInt8>?,
    _ pinnedPublicKeyLength: Int,
    _ authenticatedPeer: Bool,
    _ receivedAtMonotonicNs: UInt64,
    _ receivedAtUnixSeconds: UInt64
) -> Bool

/// Native bridge to the compiled, signature-verified Hawk local policy snapshot.
/// It has no network dependency. The native bridge blocks only an established
/// governed identity in enforce mode; unresolved flows remain unverified.
private final class HawkLocalNetworkDecisionEngine {
    static let shared = HawkLocalNetworkDecisionEngine()

    func evaluate(_ context: HawkNetworkFlowContext) -> HawkNetworkAction {
        let rawVerdict = context.sourceProcessAuditToken.withUnsafeBytes { processBytes in
            context.sourceApplicationAuditToken.withUnsafeBytes { applicationBytes in
                context.destinationHost.withUnsafeBytes { hostBytes in
                    HawkEvaluateNetworkFlow(
                        processBytes.bindMemory(to: UInt8.self).baseAddress,
                        processBytes.count,
                        applicationBytes.bindMemory(to: UInt8.self).baseAddress,
                        applicationBytes.count,
                        hostBytes.bindMemory(to: UInt8.self).baseAddress,
                        hostBytes.count,
                        context.destinationPort,
                        context.protocolNumber,
                        context.socketFamily
                    )
                }
            }
        }
        switch rawVerdict {
        case 1:
            return .allow
        case 2:
            return .localEscalationRequired
        default:
            return .block
        }
    }
}

final class HawkNetworkFilterDataProvider: NEFilterDataProvider {
    private let decisionEngine = HawkLocalNetworkDecisionEngine.shared

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        guard let configuration = filterConfiguration.vendorConfiguration,
              let envelope = configuration["HawkPolicyEnvelope"] as? Data,
              let publicKey = configuration["HawkPolicySigningPublicKeyX963"] as? Data,
              !envelope.isEmpty,
              publicKey.count == 65 else {
            completionHandler(NSError(
                domain: "ai.hawk.endpoint.policy",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Signed Hawk policy is missing"]
            ))
            return
        }
        let installed = envelope.withUnsafeBytes { envelopeBytes in
            publicKey.withUnsafeBytes { keyBytes in
                HawkMacVerifyAndInstallPolicyEnvelope(
                    envelopeBytes.bindMemory(to: UInt8.self).baseAddress,
                    envelopeBytes.count,
                    keyBytes.bindMemory(to: UInt8.self).baseAddress,
                    keyBytes.count,
                    true,
                    DispatchTime.now().uptimeNanoseconds,
                    UInt64(Date().timeIntervalSince1970)
                )
            }
        }
        guard installed else {
            completionHandler(NSError(
                domain: "ai.hawk.endpoint.policy",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Hawk policy verification failed"]
            ))
            return
        }
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        let socketFlow = flow as? NEFilterSocketFlow
        guard let context = HawkNetworkFlowContext.from(
            isSocketFlow: socketFlow != nil,
            sourceProcessAuditToken: flow.sourceProcessAuditToken,
            sourceApplicationAuditToken: flow.sourceAppAuditToken,
            endpoint: socketFlow?.remoteFlowEndpoint,
            protocolNumber: socketFlow?.socketProtocol ?? 0,
            socketFamily: socketFlow?.socketFamily ?? 0
        ) else {
            // No actor has been proven governed, so a missing token or an
            // unsupported flow shape cannot authorize a global block.
            return .allow()
        }
        switch decisionEngine.evaluate(context) {
        case .allow:
            return .allow()
        case .block, .localEscalationRequired:
            return .drop()
        }
    }
}
