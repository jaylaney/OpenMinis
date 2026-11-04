import Foundation

protocol StatusBackupExclusion: Sendable {
    func applyAndVerify(_ directory: URL) throws
}

struct FoundationStatusBackupExclusion: StatusBackupExclusion {
    func applyAndVerify(_ directory: URL) throws {
        var directory = directory
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try directory.setResourceValues(values)
        // Discard Foundation's cached resource values before verifying the write.
        directory.removeAllCachedResourceValues()
        guard try directory.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true else {
            throw JournalStorageError(kind: .filesystem, message: "Status backup exclusion was not applied")
        }
    }
}

/// Synchronous queue-confined storage. Its only database is the status-profile
/// admission.sqlite3, retaining the stable lock through SQLite connection closure.
final class StatusOnlyJournal {
    private let database: SQLiteDatabase

    private init(database: SQLiteDatabase) { self.database = database }

    static func open(configuration: StatusOnlyHostConfiguration,
                     native: any SQLiteNative = SystemSQLiteNative(),
                     backupExclusion: any StatusBackupExclusion = FoundationStatusBackupExclusion()) throws -> StatusOnlyJournal {
        let directory = try JournalStateDirectory.prepare(configuration.directory)
        let lock = try JournalDirectoryLock(directory: directory)
        defer { withExtendedLifetime(lock) {} }
        let probe = try StatusStorePreflight.inspectOwned(directory: directory)
        let main = directory.appendingPathComponent("admission.sqlite3")
        let saved: StatusStoredPolicy?
        let identity: Data
        if probe.isFresh {
            saved = nil
            identity = try configuration.identityResolver(nil)
            try StatusSchema.validateSPKI(identity)
        } else {
            let validator = try StatusReadOnlyDatabase(url: main, native: native)
            do {
                let policy = try StatusSchema.validate(read: validator.query)
                saved = policy
                identity = try configuration.identityResolver(policy.hostPin)
                try StatusSchema.validateSPKI(identity)
                guard StatusSchema.fingerprint(identity) == policy.hostPin else {
                    throw JournalStorageError(kind: .invalidState, message: "Status host identity disagrees with the saved pin")
                }
                try validator.close()
            } catch {
                // Explicitly close before releasing directory ownership on refusal.
                try? validator.close()
                throw error
            }
        }
        // Do not let the resolver or validator mutate state between inspection
        // and writable open, including during a fresh identity resolution.
        try StatusStorePreflight.recheck(probe)
        let initialIDs: (UUID, UUID, UUID)?
        if probe.isFresh {
            initialIDs = (try randomUUID(configuration.random), try randomUUID(configuration.random), try randomUUID(configuration.random))
        } else { initialIDs = nil }
        let database = try SQLiteDatabase(url: main, ownershipLock: lock, native: native)
        if let (hostID, epoch, controllerID) = initialIDs {
            try database.transaction {
                try database.execute("PRAGMA application_id = 1330467668")
                try database.execute("PRAGMA user_version = 1")
                try database.execute(StatusSchema.ddl)
                try database.execute("INSERT INTO prototype_status VALUES (1, ?, ?, ?, ?, 1, 'unenrolled', NULL)", [
                    .text(hostID.uuidString.lowercased()), .text(epoch.uuidString.lowercased()),
                    .text(StatusSchema.hex(StatusSchema.fingerprint(identity))), .text(controllerID.uuidString.lowercased())
                ])
            }
        }
        let validated = try StatusSchema.validate { try database.query($0) }
        guard validated.hostPin == StatusSchema.fingerprint(identity), saved == nil || saved == validated else {
            throw JournalStorageError(kind: .invalidState, message: "Status identity/policy changed at writable open")
        }
        try backupExclusion.applyAndVerify(directory)
        return StatusOnlyJournal(database: database)
    }

    func readPolicy() throws -> StatusStoredPolicy {
        try checkHealth()
        return try StatusSchema.validate { try database.query($0) }
    }

    func confirm(key: Data) throws -> StatusStoredPolicy {
        try checkHealth()
        try StatusSchema.validateSPKI(key)
        return try database.transaction {
            let policy = try readPolicy()
            guard policy.controllerState == .unenrolled else { throw StatusHostError.alreadyEnrolled }
            try database.execute("UPDATE prototype_status SET controller_state = 'enrolled', controller_spki_der_hex = ? WHERE singleton = 1", [.text(StatusSchema.hex(key))])
            return try readPolicy()
        }
    }

    func revoke() throws -> StatusStoredPolicy {
        try checkHealth()
        return try database.transaction {
            let policy = try readPolicy()
            switch policy.controllerState {
            case .unenrolled: throw StatusHostError.notEnrolled
            case .revoked: return policy
            case .enrolled:
                guard policy.controllerGeneration < UInt64(Int64.max) else { throw StatusHostError.generationOverflow }
                try database.execute("UPDATE prototype_status SET controller_state = 'revoked', controller_generation = controller_generation + 1 WHERE singleton = 1")
                return try readPolicy()
            }
        }
    }

    func checkHealth() throws { try database.checkHealth() }

    private static func randomUUID(_ random: any StatusRandomSource) throws -> UUID {
        let data = try random.bytes(count: 16)
        guard data.count == 16, data.contains(where: { $0 != 0 }) else {
            throw JournalStorageError(kind: .invalidState, message: "Status UUID source returned invalid bytes")
        }
        var bytes = Array(data)
        bytes[6] = (bytes[6] & 0x0f) | 0x40
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}
