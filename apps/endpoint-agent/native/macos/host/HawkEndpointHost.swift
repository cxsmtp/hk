import AppKit
import Foundation
import SystemExtensions

@main
final class HawkEndpointHost: NSObject, NSApplicationDelegate, OSSystemExtensionRequestDelegate {
    private let extensionIdentifiers = [
        "ai.hawk.endpoint.endpoint-security",
        "ai.hawk.endpoint.content-filter",
        "ai.hawk.endpoint.managed-routing",
    ]

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Activation is deliberately admin/MDM initiated. Merely launching the
        // host application must never turn inline enforcement on.
        if CommandLine.arguments.count > 1 {
            handleManagedCommand(CommandLine.arguments[1])
        }
    }

    private func handleManagedCommand(_ command: String) {
        let allowed = ["status", "apply-managed-monitor-policy", "apply-managed-enforce-policy", "activate-managed-extensions", "deactivate-managed-extensions"]
        guard allowed.contains(command) else {
            print("{\"schema\":\"hawk.macos-native-status\",\"mode\":\"disarmed\",\"healthy\":false,\"reason_codes\":[\"unsupported_command\"]}")
            NSApp.terminate(nil)
            return
        }
        if command == "activate-managed-extensions" {
            activateManagedExtensions()
            return
        }
        if command == "deactivate-managed-extensions" {
            deactivateManagedExtensions()
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            self.runManagedCommand(command)
        }
    }

    private func runManagedCommand(_ command: String) {
        do {
            let configURL = URL(fileURLWithPath: "/Library/Managed Preferences/ai.hawk.endpoint.host.plist")
            let status: [String: Any]
            if command == "apply-managed-monitor-policy" || command == "apply-managed-enforce-policy" {
                let request = try HawkManagedApplyRequest.read(command: command)
                status = try HawkEndpointPolicyClient().apply(request.configuration)
            } else {
                let configuration = try HawkManagedConfiguration.load(from: configURL)
                status = try HawkEndpointPolicyClient().status(configuration)
            }
            let data = try JSONSerialization.data(withJSONObject: status, options: [])
            print(String(data: data, encoding: .utf8) ?? "{}")
        } catch {
            print("{\"schema\":\"hawk.macos-native-status\",\"mode\":\"disarmed\",\"policy_signed\":false,\"policy_current\":false,\"healthy\":false,\"reason_codes\":[\"managed_configuration_unavailable\"]}")
        }
        DispatchQueue.main.async { NSApp.terminate(nil) }
    }

    func activateManagedExtensions() {
        for identifier in extensionIdentifiers {
            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: identifier,
                queue: .main
            )
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    func deactivateManagedExtensions() {
        for identifier in extensionIdentifiers {
            let request = OSSystemExtensionRequest.deactivationRequest(
                forExtensionWithIdentifier: identifier,
                queue: .main
            )
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension newExtension: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        guard newExtension.bundleIdentifier == existing.bundleIdentifier,
              newExtension.bundleVersion.compare(
                existing.bundleVersion,
                options: .numeric
              ) != .orderedAscending else {
            return .cancel
        }
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // MDM supplies approval in enterprise deployment. Local development
        // truthfully remains pending until the user approves System Settings.
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {}

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        NSLog("Hawk system-extension request failed: %@", String(describing: error))
    }
}
