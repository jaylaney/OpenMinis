import Foundation
import Security
import XCTest
import RemotePrototypeWire
@testable import RemotePrototypeTransport

final class PrototypeKeyStoreTests: XCTestCase {
    // Catches treating missing, unreadable or malformed existing identity as permission to rotate.
    func testMissingExistingIdentityNeverRotates() throws {
        let client = MemoryKeychain()
        let store = PrototypeKeyStore(client: client)
        XCTAssertNil(try store.loadIdentity(role: .host))
        XCTAssertEqual(client.calls.map(\.kind), [.read])
        client.readFailure = errSecInteractionNotAllowed
        assertStatus(errSecInteractionNotAllowed) { _ = try store.createIdentityIfAbsent(role: .host) }
        XCTAssertEqual(client.calls.map(\.kind), [.read, .read])
        client.readFailure = nil
        client.items["org.openminis.prototype.host.identity.v1"] = Data([1,2,3]) as CFData
        XCTAssertThrowsError(try store.createIdentityIfAbsent(role: .host))
        XCTAssertFalse(client.calls.contains { $0.kind == .add })
        let wrong = try XCTUnwrap(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 384] as CFDictionary, nil))
        client.items["org.openminis.prototype.host.identity.v1"] = wrong
        XCTAssertThrowsError(try store.createIdentityIfAbsent(role: .host))
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(wrong))
        client.items["org.openminis.prototype.host.identity.v1"] = publicKey
        XCTAssertThrowsError(try store.createIdentityIfAbsent(role: .host))
        for call in client.calls {
            XCTAssertNil(call.query[kSecAttrKeyType as String])
            XCTAssertNil(call.query[kSecAttrKeySizeInBits as String])
        }
        XCTAssertFalse(client.calls.contains { $0.kind == .add })
    }

    // Catches service collisions, wrong key protection/default group or rotating on repeated create.
    @MainActor func testQueriesUseOnlyPrototypeServices() async throws {
        let client = MemoryKeychain()
        let store = PrototypeKeyStore(client: client)
        let host = try store.createIdentityIfAbsent(role: .host)
        let controller = try store.createIdentityIfAbsent(role: .controller)
        XCTAssertEqual(try publicBytes(store.createIdentityIfAbsent(role: .host)), try publicBytes(host))
        XCTAssertNotEqual(try publicBytes(host), try publicBytes(controller))
        let record = try record()
        try store.savePairedHost(record)
        XCTAssertEqual(try store.loadPairedHost(), record)
        let literalRecord = Data([1, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]) + Data(repeating: 7, count: 32) + Data([100,64,1,2,192,0])
        XCTAssertEqual(client.items[MemoryKeychain.pinSlot] as? Data, literalRecord)
        let changedEndpoint = try PairedHostRecord(hostID: record.hostID, hostPin: record.hostPin, endpoint: StatusEndpoint(ipv4: "100.64.2.3", port: 49153))
        try store.savePairedHost(changedEndpoint)
        XCTAssertEqual(try store.loadPairedHost(), changedEndpoint)
        try store.forgetPairedHost()
        let adds = client.calls.filter { $0.kind == .add }
        XCTAssertEqual(adds.count, 3)
        for call in client.calls {
            #if os(macOS)
            XCTAssertEqual(call.query[kSecUseDataProtectionKeychain as String] as? Bool, true)
            #endif
            XCTAssertEqual(call.query[kSecAttrSynchronizable as String] as? Bool, false)
            XCTAssertNil(call.query[kSecAttrAccessGroup as String])
            if call.kind == .add {
                XCTAssertEqual(call.query[kSecAttrAccessible as String] as? String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
            }
            if call.query[kSecClass as String] as? String == kSecClassKey as String {
                let tag = try XCTUnwrap(call.query[kSecAttrApplicationTag as String] as? Data)
                XCTAssertTrue(["org.openminis.prototype.host.identity.v1", "org.openminis.prototype.controller.identity.v1"].contains(String(decoding: tag, as: UTF8.self)))
                XCTAssertNil(call.query[kSecAttrService as String])
            } else {
                XCTAssertEqual(call.query[kSecClass as String] as? String, kSecClassGenericPassword as String)
                XCTAssertEqual(call.query[kSecAttrService as String] as? String, "org.openminis.prototype.controller.hostpins.v1")
                XCTAssertEqual(call.query[kSecAttrAccount as String] as? String, "paired-host")
            }
        }
        let update = try XCTUnwrap(client.calls.first { $0.kind == .update })
        XCTAssertEqual(update.attributes?[kSecAttrSynchronizable as String] as? Bool, false)
        XCTAssertEqual(update.attributes?[kSecAttrAccessible as String] as? String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
    }

    // Catches broad/class-wide deletion, identity deletion and swallowing real deletion failures.
    @MainActor func testForgetDeletesOnlyPairedHost() async throws {
        let client = MemoryKeychain()
        let store = PrototypeKeyStore(client: client)
        let identity = try store.createIdentityIfAbsent(role: .controller)
        client.items["unrelated-sentinel"] = Data([9]) as CFData
        try store.savePairedHost(record())
        try store.forgetPairedHost()
        XCTAssertNil(try store.loadPairedHost())
        XCTAssertEqual(try publicBytes(XCTUnwrap(store.loadIdentity(role: .controller))), try publicBytes(identity))
        XCTAssertEqual(client.items["unrelated-sentinel"] as? Data, Data([9]))
        try store.forgetPairedHost()
        let deletes = client.calls.filter { $0.kind == .delete }
        XCTAssertEqual(deletes.count, 2)
        for delete in deletes {
            #if os(macOS)
            XCTAssertEqual(Set(delete.query.keys), Set([kSecClass, kSecAttrService, kSecAttrAccount, kSecAttrSynchronizable, kSecUseDataProtectionKeychain].map { $0 as String }))
            #endif
        }
        client.deleteFailure = errSecMissingEntitlement
        assertStatus(errSecMissingEntitlement) { try store.forgetPairedHost() }
    }

    // Catches a tentative replacement pin/host overwriting pairing, and malformed records becoming fresh.
    @MainActor func testSavedPairingCannotBeReplacedAndMalformedIsUnavailable() async throws {
        let client = MemoryKeychain()
        let store = PrototypeKeyStore(client: client)
        let original = try record()
        try store.savePairedHost(original)
        let otherPin = try PairedHostRecord(hostID: original.hostID, hostPin: Data(repeating: 8, count: 32), endpoint: original.endpoint)
        let otherHost = try PairedHostRecord(hostID: UUID(), hostPin: original.hostPin, endpoint: original.endpoint)
        XCTAssertThrowsError(try store.savePairedHost(otherPin))
        XCTAssertThrowsError(try store.savePairedHost(otherHost))
        XCTAssertEqual(try store.loadPairedHost(), original)
        let writes = client.calls.filter { $0.kind == .add || $0.kind == .update }.count
        let validBytes = Data([1, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]) + Data(repeating: 7, count: 32) + Data([100,64,1,2,192,0])
        var zeroID = validBytes; zeroID.replaceSubrange(1..<17, with: Data(count: 16))
        var badAddress = validBytes; badAddress[49] = 127
        var badPort = validBytes; badPort[53] = 3; badPort[54] = 255
        var unknownVersion = validBytes; unknownVersion[0] = 2
        for bytes in [Data(), Data([1]), Data(repeating: 0, count: 55), zeroID, badAddress, badPort, unknownVersion, validBytes + Data([0])] {
            client.items[MemoryKeychain.pinSlot] = bytes as CFData
            XCTAssertThrowsError(try store.loadPairedHost())
            XCTAssertThrowsError(try store.savePairedHost(original))
        }
        XCTAssertEqual(client.calls.filter { $0.kind == .add || $0.kind == .update }.count, writes)
        XCTAssertThrowsError(try PairedHostRecord(hostID: UUID(uuidString: "00000000-0000-0000-0000-000000000000")!, hostPin: Data(count: 32), endpoint: original.endpoint))
        XCTAssertThrowsError(try PairedHostRecord(hostID: UUID(), hostPin: Data(count: 31), endpoint: original.endpoint))
    }

    // Catches permission/signing failures retried against another Keychain or ignored on mutation.
    @MainActor func testErrorsPropagateWithoutFallback() async throws {
        let client = MemoryKeychain()
        let store = PrototypeKeyStore(client: client)
        client.addFailure = errSecMissingEntitlement
        assertStatus(errSecMissingEntitlement) { _ = try store.createIdentityIfAbsent(role: .host) }
        XCTAssertEqual(client.calls.map(\.kind), [.read, .add])
        client.calls.removeAll()
        assertStatus(errSecMissingEntitlement) { try store.savePairedHost(record()) }
        XCTAssertEqual(client.calls.map(\.kind), [.read, .add])
        client.addFailure = nil
        try store.savePairedHost(record())
        client.updateFailure = errSecInteractionNotAllowed
        let changed = try PairedHostRecord(hostID: record().hostID, hostPin: record().hostPin, endpoint: StatusEndpoint(ipv4: "100.64.2.3", port: 49153))
        assertStatus(errSecInteractionNotAllowed) { try store.savePairedHost(changed) }
        client.readFailure = errSecAuthFailed
        assertStatus(errSecAuthFailed) { _ = try store.loadPairedHost() }
        assertStatus(errSecAuthFailed) { try store.savePairedHost(changed) }
    }

    private func record() throws -> PairedHostRecord {
        try PairedHostRecord(hostID: UUID(uuidString: "01020304-0506-0708-090a-0b0c0d0e0f10")!, hostPin: Data(repeating: 7, count: 32), endpoint: StatusEndpoint(ipv4: "100.64.1.2", port: 49152))
    }
    private func publicBytes(_ key: SecKey) throws -> Data {
        try XCTUnwrap(SecKeyCopyExternalRepresentation(XCTUnwrap(SecKeyCopyPublicKey(key)), nil)) as Data
    }
    private func assertStatus(_ expected: OSStatus, _ operation: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            XCTAssertEqual(error as? PrototypeKeyStoreError, .keychain(expected), file: file, line: line)
        }
    }
}

// Only the SecItem boundary is substituted. Every generated key is nonpersistent/in memory.
private final class MemoryKeychain: PrototypeKeychainClient {
    enum Kind: Equatable { case read, add, update, delete }
    struct Call { let kind: Kind; let query: [String: Any]; var attributes: [String: Any]? = nil }
    static let pinSlot = "org.openminis.prototype.controller.hostpins.v1/paired-host"
    var items: [String: CFTypeRef] = [:]
    var calls: [Call] = []
    var readFailure: OSStatus?
    var addFailure: OSStatus?
    var updateFailure: OSStatus?
    var deleteFailure: OSStatus?
    func copyMatching(_ query: [String: Any]) -> (OSStatus, CFTypeRef?) {
        calls.append(Call(kind: .read, query: query))
        if let readFailure { return (readFailure, nil) }
        guard let value = items[slot(query)] else { return (errSecItemNotFound, nil) }
        return (errSecSuccess, value)
    }
    func add(_ attributes: [String: Any]) -> OSStatus {
        calls.append(Call(kind: .add, query: attributes))
        if let addFailure { return addFailure }
        let key = slot(attributes)
        guard items[key] == nil else { return errSecDuplicateItem }
        items[key] = attributes[kSecValueRef as String] as CFTypeRef? ?? attributes[kSecValueData as String] as CFTypeRef?
        return errSecSuccess
    }
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        calls.append(Call(kind: .update, query: query, attributes: attributes))
        if let updateFailure { return updateFailure }
        guard items[slot(query)] != nil else { return errSecItemNotFound }
        items[slot(query)] = attributes[kSecValueData as String] as CFTypeRef?
        return errSecSuccess
    }
    func delete(_ query: [String: Any]) -> OSStatus {
        calls.append(Call(kind: .delete, query: query))
        if let deleteFailure { return deleteFailure }
        return items.removeValue(forKey: slot(query)) == nil ? errSecItemNotFound : errSecSuccess
    }
    private func slot(_ query: [String: Any]) -> String {
        if let tag = query[kSecAttrApplicationTag as String] as? Data { return String(decoding: tag, as: UTF8.self) }
        return "\(query[kSecAttrService as String] as? String ?? "")/\(query[kSecAttrAccount as String] as? String ?? "")"
    }
}
