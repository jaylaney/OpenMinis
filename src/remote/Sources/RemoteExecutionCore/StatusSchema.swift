import CSQLite
import CryptoKit
import Foundation

enum StatusSchema {
    static let applicationID = 1330467668
    static let version = 1

    // Frozen design DDL. Keep the stored SQL byte-for-byte; do not normalize it.
    static let ddl = """
    CREATE TABLE prototype_status (
        singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1),
        host_id TEXT NOT NULL UNIQUE CHECK(typeof(host_id) = 'text' AND length(host_id) = 36),
        storage_epoch TEXT NOT NULL UNIQUE CHECK(typeof(storage_epoch) = 'text' AND length(storage_epoch) = 36),
        host_spki_sha256 TEXT NOT NULL CHECK(typeof(host_spki_sha256) = 'text' AND length(host_spki_sha256) = 64 AND host_spki_sha256 NOT GLOB '*[^0-9a-f]*'),
        controller_id TEXT NOT NULL UNIQUE CHECK(typeof(controller_id) = 'text' AND length(controller_id) = 36),
        controller_generation INTEGER NOT NULL CHECK(typeof(controller_generation) = 'integer' AND controller_generation >= 1),
        controller_state TEXT NOT NULL CHECK(controller_state IN ('unenrolled', 'enrolled', 'revoked')),
        controller_spki_der_hex TEXT CHECK(controller_spki_der_hex IS NULL OR (typeof(controller_spki_der_hex) = 'text' AND length(controller_spki_der_hex) = 182 AND controller_spki_der_hex NOT GLOB '*[^0-9a-f]*')),
        CHECK((controller_state = 'unenrolled' AND controller_spki_der_hex IS NULL) OR (controller_state IN ('enrolled', 'revoked') AND controller_spki_der_hex IS NOT NULL))
    )
    """

    private static let objectsSQL = "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name"
    private static let indexesSQL = "PRAGMA index_list('prototype_status')"
    private static let indexNames = (1...3).map { "sqlite_autoindex_prototype_status_\($0)" }

    static func validate(read: (String) throws -> [[String?]]) throws -> StatusStoredPolicy {
        guard try read("PRAGMA application_id") == [["1330467668"]],
              try read("PRAGMA user_version") == [["1"]] else { throw invalid("Wrong status store identity/version") }
        try compareReference(read: read)
        guard try read("PRAGMA integrity_check") == [["ok"]] else { throw invalid("Status integrity check failed") }
        let fields = ["singleton", "host_id", "storage_epoch", "host_spki_sha256", "controller_id", "controller_generation", "controller_state", "controller_spki_der_hex"]
        let rows = try read("SELECT " + fields.joined(separator: ", ") + ", " + fields.map { "typeof(\($0))" }.joined(separator: ", ") + " FROM prototype_status")
        guard rows.count == 1, let row = rows.first, row.count == 16,
              row[0] == "1", row[8] == "integer",
              row[9] == "text", row[10] == "text", row[11] == "text", row[12] == "text",
              row[13] == "integer", row[14] == "text",
              let hostID = canonicalUUID(row[1]), let epoch = canonicalUUID(row[2]),
              let pin = decodeHex(row[3], count: 32), let controllerID = canonicalUUID(row[4]),
              let rawGeneration = row[5], let generation = Int64(rawGeneration), generation >= 1,
              let rawState = row[6], let state = StatusControllerState(rawValue: rawState) else {
            throw invalid("Invalid singleton status policy")
        }
        let controllerKey: Data?
        switch state {
        case .unenrolled:
            guard row[7] == nil, row[15] == "null" else { throw invalid("Unenrolled policy has a controller key") }
            controllerKey = nil
        case .enrolled, .revoked:
            guard row[15] == "text", let key = decodeHex(row[7], count: 91) else { throw invalid("Missing controller key") }
            do { try validateSPKI(key) } catch { throw invalid("Invalid controller P256 SPKI") }
            controllerKey = key
        }
        return StatusStoredPolicy(hostID: hostID, storageEpoch: epoch, controllerID: controllerID,
                                  controllerGeneration: UInt64(generation), controllerState: state,
                                  controllerSPKI: controllerKey, hostPin: pin)
    }

    static func validateSPKI(_ data: Data) throws {
        guard data.count == 91, let key = try? P256.Signing.PublicKey(derRepresentation: data),
              key.derRepresentation == data else { throw StatusHostError.invalidKey }
    }

    static func fingerprint(_ key: Data) -> Data { Data(SHA256.hash(data: key)) }
    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    private static func canonicalUUID(_ text: String?) -> UUID? {
        guard let text, text.utf8.count == 36, let uuid = UUID(uuidString: text),
              uuid.uuidString.lowercased() == text,
              text != "00000000-0000-0000-0000-000000000000" else { return nil }
        return uuid
    }

    private static func decodeHex(_ text: String?, count: Int) -> Data? {
        guard let text, text.utf8.count == count * 2 else { return nil }
        let bytes = Array(text.utf8)
        func nibble(_ byte: UInt8) -> UInt8? {
            switch byte { case 48...57: return byte - 48; case 97...102: return byte - 87; default: return nil }
        }
        var data = Data(capacity: count)
        for offset in stride(from: 0, to: bytes.count, by: 2) {
            guard let high = nibble(bytes[offset]), let low = nibble(bytes[offset + 1]) else { return nil }
            data.append(high * 16 + low)
        }
        return data
    }

    private static func compareReference(read: (String) throws -> [[String?]]) throws {
        var opened: OpaquePointer?
        let result = sqlite3_open_v2(":memory:", &opened, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil)
        guard result == SQLITE_OK, let reference = opened else {
            if let opened { sqlite3_close_v2(opened) }
            throw invalid("Cannot instantiate status schema reference")
        }
        defer { sqlite3_close_v2(reference) }
        guard sqlite3_exec(reference, ddl, nil, nil, nil) == SQLITE_OK else { throw SystemSQLiteNative().failure(reference) }
        let queries = [objectsSQL, indexesSQL] + indexNames.map { "PRAGMA index_xinfo('\($0)')" }
        for query in queries {
            guard try read(query) == StatusReadOnlyDatabase.read(query, connection: reference) else {
                throw invalid("Status schema differs from frozen reference")
            }
        }
    }

    private static func invalid(_ message: String) -> JournalStorageError {
        JournalStorageError(kind: .invalidState, message: message)
    }
}
