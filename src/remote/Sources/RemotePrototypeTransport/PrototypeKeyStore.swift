import Foundation
import CryptoKit
import Security
import RemotePrototypeWire

public enum PrototypeIdentityRole: Sendable {
    case host, controller

    fileprivate var tag: Data {
        Data((self == .host ? "org.openminis.prototype.host.identity.v1" : "org.openminis.prototype.controller.identity.v1").utf8)
    }
}

public enum PrototypeKeyStoreError: Error, Equatable, Sendable {
    case keychain(OSStatus)
    case malformedIdentity
    case malformedPairing
    case pairingConflict
}

public struct PairedHostRecord: Equatable, Sendable {
    public let hostID: UUID
    public let hostPin: Data
    public let endpoint: StatusEndpoint

    public init(hostID: UUID, hostPin: Data, endpoint: StatusEndpoint) throws {
        guard hostID != UUID(uuid: (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)), hostPin.count == 32 else {
            throw PrototypeKeyStoreError.malformedPairing
        }
        self.hostID = hostID
        self.hostPin = hostPin
        self.endpoint = endpoint
    }

    // Version 1: version(1), UUID(16), full SPKI SHA256 pin(32), IPv4(4), port(2, big endian).
    fileprivate var encoded: Data {
        var uuid = hostID.uuid
        let id = withUnsafeBytes(of: &uuid) { Data($0) }
        let address = Data(endpoint.ipv4.split(separator: ".").map { UInt8($0)! })
        return Data([1]) + id + hostPin + address + Data([UInt8(endpoint.port >> 8), UInt8(endpoint.port & 0xff)])
    }

    fileprivate init(encoded: Data) throws {
        guard encoded.count == 55, encoded.first == 1 else { throw PrototypeKeyStoreError.malformedPairing }
        let bytes = Array(encoded)
        let id = bytes[1..<17].withUnsafeBufferPointer { NSUUID(uuidBytes: $0.baseAddress!) as UUID }
        let endpoint: StatusEndpoint
        do {
            endpoint = try StatusEndpoint(ipv4: bytes[49..<53].map(String.init).joined(separator: "."), port: UInt16(bytes[53]) << 8 | UInt16(bytes[54]))
        } catch { throw PrototypeKeyStoreError.malformedPairing }
        try self.init(hostID: id, hostPin: Data(bytes[17..<49]), endpoint: endpoint)
    }
}

/// The only boundary substituted by query tests. Production operations never retry another Keychain.
protocol PrototypeKeychainClient {
    func copyMatching(_ query: [String: Any]) -> (OSStatus, CFTypeRef?)
    func add(_ attributes: [String: Any]) -> OSStatus
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus
    func delete(_ query: [String: Any]) -> OSStatus
}

private struct SystemPrototypeKeychain: PrototypeKeychainClient {
    func copyMatching(_ query: [String: Any]) -> (OSStatus, CFTypeRef?) {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return (status, result)
    }
    func add(_ attributes: [String: Any]) -> OSStatus { SecItemAdd(attributes as CFDictionary, nil) }
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus { SecItemUpdate(query as CFDictionary, attributes as CFDictionary) }
    func delete(_ query: [String: Any]) -> OSStatus { SecItemDelete(query as CFDictionary) }
}

/// Isolated prototype items in the signed application's default private access group.
/// Existing-owner callers must use loadIdentity and compare their required pin; only a
/// fresh-owner resolver (nil required pin) may call createIdentityIfAbsent.
public final class PrototypeKeyStore {
    private let client: any PrototypeKeychainClient
    private let identityLock = NSLock()

    public init() { self.client = SystemPrototypeKeychain() }
    init(client: any PrototypeKeychainClient) { self.client = client }

    public func loadIdentity(role: PrototypeIdentityRole) throws -> SecKey? {
        try identityLock.withLock { try readIdentity(role: role) }
    }

    public func createIdentityIfAbsent(role: PrototypeIdentityRole) throws -> SecKey {
        try identityLock.withLock {
            if let existing = try readIdentity(role: role) { return existing }
            // Explicitly ephemeral generation; persistence goes only through the injected SecItem boundary.
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateRandomKey([
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits: 256,
                kSecAttrIsPermanent: false
            ] as CFDictionary, &error) else {
                if let error { throw error.takeRetainedValue() }
                throw PrototypeKeyStoreError.malformedIdentity
            }
            var attributes = identityQuery(role: role)
            attributes[kSecValueRef as String] = key
            attributes[kSecAttrKeyType as String] = kSecAttrKeyTypeECSECPrimeRandom
            attributes[kSecAttrKeySizeInBits as String] = 256
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            try check(client.add(attributes))
            return key
        }
    }

    @MainActor public func loadPairedHost() throws -> PairedHostRecord? {
        var query = pairingQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, value) = client.copyMatching(query)
        if status == errSecItemNotFound { return nil }
        try check(status)
        guard let data = value as? Data else { throw PrototypeKeyStoreError.malformedPairing }
        return try PairedHostRecord(encoded: data)
    }

    @MainActor public func savePairedHost(_ record: PairedHostRecord) throws {
        if let existing = try loadPairedHost() {
            guard existing.hostID == record.hostID, existing.hostPin == record.hostPin else {
                throw PrototypeKeyStoreError.pairingConflict
            }
            if existing == record { return }
            // Only endpoint changes for the same authenticated identity may update an existing record.
            try check(client.update(pairingQuery(), attributes: [
                kSecValueData as String: record.encoded,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                kSecAttrSynchronizable as String: false
            ]))
        } else {
            var attributes = pairingQuery()
            attributes[kSecValueData as String] = record.encoded
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            try check(client.add(attributes))
        }
    }

    @MainActor public func forgetPairedHost() throws {
        let status = client.delete(pairingQuery())
        if status != errSecItemNotFound { try check(status) }
    }

    private func readIdentity(role: PrototypeIdentityRole) throws -> SecKey? {
        var query = identityQuery(role: role)
        query[kSecReturnRef as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, value) = client.copyMatching(query)
        if status == errSecItemNotFound { return nil }
        try check(status)
        guard let value, CFGetTypeID(value) == SecKeyGetTypeID() else { throw PrototypeKeyStoreError.malformedIdentity }
        let key = value as! SecKey
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPrivate as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256),
              let publicKey = SecKeyCopyPublicKey(key),
              let point = SecKeyCopyExternalRepresentation(publicKey, nil),
              (try? P256.Signing.PublicKey(x963Representation: point as Data)) != nil else {
            throw PrototypeKeyStoreError.malformedIdentity
        }
        return key
    }

    private func identityQuery(role: PrototypeIdentityRole) -> [String: Any] {
        // Do not filter curve/size/class: an unsupported existing tagged key must be an error, not "absent".
        protectedQuery([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: role.tag])
    }
    private func pairingQuery() -> [String: Any] {
        protectedQuery([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "org.openminis.prototype.controller.hostpins.v1",
            kSecAttrAccount as String: "paired-host"
        ])
    }
    private func protectedQuery(_ attributes: [String: Any]) -> [String: Any] {
        var attributes = attributes
        attributes[kSecAttrSynchronizable as String] = false
        #if os(macOS)
        attributes[kSecUseDataProtectionKeychain as String] = true
        #endif
        // Omit kSecAttrAccessGroup to use the signed app's private default group.
        return attributes
    }
    private func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw PrototypeKeyStoreError.keychain(status) }
    }
}
