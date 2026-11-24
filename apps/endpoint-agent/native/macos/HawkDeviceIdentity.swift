import CryptoKit
import Foundation
import Security

enum HelperFailure: Error {
    case message(String)
}

func emit(_ object: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else {
        FileHandle.standardError.write(Data("identity helper serialization failed\n".utf8))
        exit(3)
    }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

func fail(_ message: String, code: Int32 = 2) -> Never {
    emit(["ok": false, "error": message])
    exit(code)
}

func sealedReferenceURL(tag: String) throws -> URL {
    guard let support = FileManager.default.urls(
        for: .applicationSupportDirectory,
        in: .userDomainMask
    ).first else {
        throw HelperFailure.message("Application Support directory unavailable")
    }
    let directory = support
        .appendingPathComponent("Hawk", isDirectory: true)
        .appendingPathComponent("EndpointAgent", isDirectory: true)
        .appendingPathComponent("device-keys", isDirectory: true)
    try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    return directory.appendingPathComponent("\(tag).sekey", isDirectory: false)
}

func loadKey(tag: String) throws -> SecureEnclave.P256.Signing.PrivateKey? {
    let url = try sealedReferenceURL(tag: tag)
    guard FileManager.default.fileExists(atPath: url.path) else { return nil }
    let sealedReference = try Data(contentsOf: url)
    do {
        return try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: sealedReference
        )
    } catch {
        throw HelperFailure.message("Secure Enclave sealed key reference is invalid")
    }
}

func createKey(tag: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
    guard SecureEnclave.isAvailable else {
        throw HelperFailure.message("Secure Enclave is unavailable")
    }
    var accessError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        [.privateKeyUsage],
        &accessError
    ) else {
        throw HelperFailure.message("Secure Enclave access control unavailable")
    }
    let key: SecureEnclave.P256.Signing.PrivateKey
    do {
        key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    } catch {
        throw HelperFailure.message("Secure Enclave key creation failed")
    }
    let url = try sealedReferenceURL(tag: tag)
    do {
        try key.dataRepresentation.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    } catch {
        throw HelperFailure.message("hardware-sealed key reference could not be persisted")
    }
    return key
}

func ensureKey(tag: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
    if let existing = try loadKey(tag: tag) { return existing }
    return try createKey(tag: tag)
}

func publicKeyPEM(_ key: SecureEnclave.P256.Signing.PrivateKey) throws -> String {
    let external = key.publicKey.x963Representation
    guard external.count == 65, external.first == 0x04 else {
        throw HelperFailure.message("unexpected P-256 public key format")
    }
    let spkiPrefix = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
        0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
        0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ])
    let spki = spkiPrefix + external
    let compact = spki.base64EncodedString()
    var lines: [String] = []
    var offset = compact.startIndex
    while offset < compact.endIndex {
        let end = compact.index(offset, offsetBy: 64, limitedBy: compact.endIndex)
            ?? compact.endIndex
        lines.append(String(compact[offset..<end]))
        offset = end
    }
    let body = lines.joined(separator: "\n")
    return "-----BEGIN PUBLIC KEY-----\n\(body)\n-----END PUBLIC KEY-----\n"
}

guard CommandLine.arguments.count == 3 else {
    fail("usage: hawk-device-identity <ensure|status|sign|destroy> <key-tag>")
}

let operation = CommandLine.arguments[1]
let tag = CommandLine.arguments[2]
guard tag.range(
    of: "^[A-Za-z0-9._-]{1,200}$",
    options: .regularExpression
) != nil else {
    fail("invalid key tag")
}

do {
    switch operation {
    case "ensure":
        let key = try ensureKey(tag: tag)
        emit([
            "ok": true,
            "provider": "macos_secure_enclave",
            "hardware_backed": true,
            "sealed_reference": true,
            "public_key_pem": try publicKeyPEM(key),
        ])
    case "status":
        let key = try loadKey(tag: tag)
        var result: [String: Any] = [
            "ok": true,
            "provider": "macos_secure_enclave",
            "hardware_backed": true,
            "sealed_reference": true,
            "exists": key != nil,
        ]
        if let key {
            result["public_key_pem"] = try publicKeyPEM(key)
        }
        emit(result)
    case "sign":
        guard let key = try loadKey(tag: tag) else {
            throw HelperFailure.message("Secure Enclave key not found")
        }
        let payload = FileHandle.standardInput.readDataToEndOfFile()
        guard !payload.isEmpty, payload.count <= 1_048_576 else {
            throw HelperFailure.message("signing payload size is invalid")
        }
        let signature: P256.Signing.ECDSASignature
        do {
            signature = try key.signature(for: payload)
        } catch {
            throw HelperFailure.message("Secure Enclave signing failed")
        }
        let encoded = signature.derRepresentation.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        emit(["ok": true, "signature": encoded])
    case "destroy":
        let url = try sealedReferenceURL(tag: tag)
        let existed = FileManager.default.fileExists(atPath: url.path)
        if existed {
            try FileManager.default.removeItem(at: url)
        }
        emit(["ok": true, "destroyed": existed])
    default:
        fail("unsupported operation")
    }
} catch HelperFailure.message(let message) {
    fail(message)
} catch {
    fail("Secure Enclave operation failed")
}
