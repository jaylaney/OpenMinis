import CryptoKit
import Foundation

/// Synchronous storage kernel, confined to its owning coordinator. No networking,
/// authentication, OS process inspection, or process supervision occurs here.
final class AdmissionJournal {
    private let database: SQLiteDatabase
    private(set) var status: AdmissionStatus
    var epoch: StorageEpoch { status.epoch }
    var recoveryRequired: Bool { status.recoveryRequired }

    init(directory: URL, controllerID: ControllerID) throws {
        try JournalStateDirectory.prepare(directory)
        let ownershipLock = try JournalDirectoryLock(directory: directory)
        database = try SQLiteDatabase(url: directory.appendingPathComponent("admission.sqlite3"), ownershipLock: ownershipLock)
        // A temporary initialization value is replaced by persisted state before init returns.
        status = AdmissionStatus(epoch: StorageEpoch(), recoveryRequired: false, activeRun: nil)
        try database.transaction {
            try database.execute("""
                CREATE TABLE IF NOT EXISTS journal (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    epoch TEXT NOT NULL UNIQUE,
                    controller TEXT,
                    recovery INTEGER NOT NULL CHECK(recovery IN (0, 1))
                )
                """)
            try database.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY NOT NULL,
                    session_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('active', 'stopRequested', 'settled')),
                    outcome TEXT CHECK(outcome IN ('completed', 'failed', 'interruptedUnknown')),
                    CHECK((state = 'settled' AND outcome IS NOT NULL) OR (state != 'settled' AND outcome IS NULL))
                )
                """)
            try database.execute("CREATE UNIQUE INDEX IF NOT EXISTS one_active_run ON runs ((1)) WHERE state != 'settled'")
            try database.execute("""
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY NOT NULL,
                    epoch TEXT NOT NULL REFERENCES journal(epoch),
                    controller TEXT NOT NULL,
                    session_id TEXT,
                    run_id TEXT,
                    kind TEXT CHECK(kind IN ('startRun', 'stopRun')),
                    digest TEXT,
                    disposition TEXT NOT NULL CHECK(disposition IN ('admitted', 'stopRequested', 'rejectedBusy', 'rejectedAbsent', 'rejectedRunUnavailable')),
                    CHECK((disposition = 'rejectedAbsent' AND session_id IS NULL AND run_id IS NULL AND kind IS NULL AND digest IS NULL)
                       OR (disposition != 'rejectedAbsent' AND session_id IS NOT NULL AND run_id IS NOT NULL AND kind IS NOT NULL AND digest IS NOT NULL))
                )
                """)
            try database.execute("INSERT OR IGNORE INTO journal(singleton, epoch, recovery) VALUES(1, ?, 0)", [.text(StorageEpoch().rawValue.uuidString)])
            try validateController(controllerID)
            // Opening unresolved work conservatively requires host-confirmed absence.
            try database.execute("UPDATE journal SET recovery = 1 WHERE EXISTS(SELECT 1 FROM runs WHERE state != 'settled')")
            status = try readStatus()
        }
    }

    func runStatus(for runID: RunID, epoch: StorageEpoch) throws -> RunRecord? {
        let currentEpoch = try readEpoch()
        guard epoch == currentEpoch else { throw AdmissionError.staleEpoch }
        return try database.query("SELECT session_id, run_id, state, outcome FROM runs WHERE run_id = ?", [.text(runID.rawValue.uuidString)])
            .first.map { try decodeRun($0, epoch: currentEpoch) }
    }

    private func readEpoch() throws -> StorageEpoch {
        guard let epochText = try database.query("SELECT epoch FROM journal").first?[0],
              let value = UUID(uuidString: epochText) else { throw corrupt() }
        return StorageEpoch(rawValue: value)
    }

    func record(_ request: MutationRequest) throws -> SubmissionResult {
        try update {
            guard request.epoch == (try readStatus().epoch) else { throw AdmissionError.staleEpoch }
            try validateController(request.controllerID)
            let digest = fingerprint(request)
            if let existing = try lookup(request.requestID) {
                if existing.disposition == .rejectedAbsent { return SubmissionResult(record: existing, isReplay: true) }
                guard existing.digest == digest else { throw AdmissionError.payloadConflict }
                return SubmissionResult(record: existing, isReplay: true)
            }
            let current = try readStatus()
            let disposition: RequestDisposition
            switch request.kind {
            case .startRun:
                if current.recoveryRequired || current.activeRun != nil {
                    disposition = .rejectedBusy
                } else if try runStatus(for: request.runID, epoch: request.epoch) != nil {
                    disposition = .rejectedRunUnavailable
                } else {
                    try database.execute("INSERT INTO runs(run_id, session_id, state) VALUES(?, ?, 'active')", [
                        .text(request.runID.rawValue.uuidString), .text(request.sessionID.rawValue.uuidString)
                    ])
                    disposition = .admitted
                }
            case .stopRun:
                if let active = current.activeRun, active.runID == request.runID, active.sessionID == request.sessionID {
                    try database.execute("UPDATE runs SET state = 'stopRequested' WHERE run_id = ?", [.text(request.runID.rawValue.uuidString)])
                    disposition = .stopRequested
                } else {
                    disposition = .rejectedRunUnavailable
                }
            }
            let record = RequestRecord(epoch: request.epoch, controllerID: request.controllerID,
                requestID: request.requestID, sessionID: request.sessionID, runID: request.runID,
                kind: request.kind, digest: digest, disposition: disposition)
            try insert(record)
            return SubmissionResult(record: record, isReplay: false)
        }
    }

    func lookupOrRejectAbsent(_ requestID: RequestID, controllerID: ControllerID) throws -> RequestRecord {
        try update {
            try validateController(controllerID)
            if let existing = try lookup(requestID) { return existing }
            let record = RequestRecord(epoch: try readStatus().epoch, controllerID: controllerID,
                requestID: requestID, sessionID: nil, runID: nil, kind: nil, digest: nil, disposition: .rejectedAbsent)
            try insert(record)
            return record
        }
    }

    /// Host-internal settlement: use the admitted run's epoch after observing actual termination.
    func settle(runID: RunID, epoch: StorageEpoch, outcome: RunOutcome) throws {
        try update {
            guard epoch == (try readEpoch()) else { throw AdmissionError.staleEpoch }
            guard let run = try runStatus(for: runID, epoch: epoch) else { throw AdmissionError.invalidTransition }
            if run.state == .settled {
                guard run.outcome == outcome else { throw AdmissionError.invalidTransition }
                return
            }
            guard try !readStatus().recoveryRequired else { throw AdmissionError.recoveryRequired }
            try settleUnresolved(runID, outcome: outcome)
        }
    }

    /// The authenticated host must independently confirm that recovered processes are absent.
    /// Command exit evidence does not prove that the agent run completed. Recovery
    /// conservatively records interruptedUnknown and never resumes a command or loop.
    func confirmRecoveredProcessesAbsent() throws {
        try update {
            let current = try readStatus()
            guard current.recoveryRequired else { return }
            if let active = current.activeRun { try settleUnresolved(active.runID, outcome: .interruptedUnknown) }
            try database.execute("UPDATE journal SET recovery = 0")
        }
    }

    func reset() throws -> StorageEpoch {
        try update {
            let current = try readStatus()
            guard !current.recoveryRequired else { throw AdmissionError.recoveryRequired }
            guard current.activeRun == nil else { throw AdmissionError.invalidTransition }
            let next = StorageEpoch()
            try database.execute("DELETE FROM requests")
            try database.execute("DELETE FROM runs")
            try database.execute("UPDATE journal SET epoch = ?, recovery = 0", [.text(next.rawValue.uuidString)])
            return next
        }
    }

    private func update<T>(_ body: () throws -> T) throws -> T {
        let (result, nextStatus) = try database.transaction {
            let result = try body()
            return (result, try readStatus())
        }
        status = nextStatus
        return result
    }

    private func validateController(_ controllerID: ControllerID) throws {
        guard let row = try database.query("SELECT controller FROM journal").first else { throw corrupt() }
        if let controller = row[0] {
            guard controller == controllerID.rawValue.uuidString else { throw AdmissionError.wrongController }
        } else {
            try database.execute("UPDATE journal SET controller = ?", [.text(controllerID.rawValue.uuidString)])
        }
    }

    private func settleUnresolved(_ runID: RunID, outcome: RunOutcome) throws {
        try database.execute("UPDATE runs SET state = 'settled', outcome = ? WHERE run_id = ?", [
            .text(outcome.rawValue), .text(runID.rawValue.uuidString)
        ])
    }

    private func readStatus() throws -> AdmissionStatus {
        guard let row = try database.query("SELECT epoch, recovery FROM journal").first,
              let epochText = row[0], let uuid = UUID(uuidString: epochText),
              let recovery = row[1], recovery == "0" || recovery == "1" else { throw corrupt() }
        let epoch = StorageEpoch(rawValue: uuid)
        let active = try database.query("SELECT session_id, run_id, state, outcome FROM runs WHERE state != 'settled'")
            .first.map { try decodeRun($0, epoch: epoch) }
        return AdmissionStatus(epoch: epoch, recoveryRequired: recovery == "1", activeRun: active)
    }

    private func decodeRun(_ row: [String?], epoch: StorageEpoch) throws -> RunRecord {
        guard let sessionText = row[0], let session = UUID(uuidString: sessionText),
              let runText = row[1], let run = UUID(uuidString: runText),
              let stateText = row[2], let state = RunState(rawValue: stateText) else { throw corrupt() }
        let outcome = try row[3].map { text in
            guard let value = RunOutcome(rawValue: text) else { throw corrupt() }
            return value
        }
        return RunRecord(epoch: epoch, sessionID: SessionID(rawValue: session), runID: RunID(rawValue: run), state: state, outcome: outcome)
    }

    private func lookup(_ id: RequestID) throws -> RequestRecord? {
        guard let row = try database.query("SELECT epoch, controller, session_id, run_id, kind, digest, disposition FROM requests WHERE request_id = ?", [.text(id.rawValue.uuidString)]).first else { return nil }
        guard let epochText = row[0], let epoch = UUID(uuidString: epochText),
              let controllerText = row[1], let controller = UUID(uuidString: controllerText),
              let dispositionText = row[6], let disposition = RequestDisposition(rawValue: dispositionText) else { throw corrupt() }
        let session = try row[2].map { text in
            guard let value = UUID(uuidString: text) else { throw corrupt() }
            return SessionID(rawValue: value)
        }
        let run = try row[3].map { text in
            guard let value = UUID(uuidString: text) else { throw corrupt() }
            return RunID(rawValue: value)
        }
        let kind = try row[4].map { text in
            guard let value = MutationKind(rawValue: text) else { throw corrupt() }
            return value
        }
        let digest = try row[5].map { text in
            guard let value = Data(base64Encoded: text), value.count == SHA256.byteCount else { throw corrupt() }
            return value
        }
        return RequestRecord(epoch: StorageEpoch(rawValue: epoch), controllerID: ControllerID(rawValue: controller),
            requestID: id, sessionID: session, runID: run, kind: kind, digest: digest, disposition: disposition)
    }

    private func insert(_ record: RequestRecord) throws {
        try database.execute("INSERT INTO requests(request_id, epoch, controller, session_id, run_id, kind, digest, disposition) VALUES(?, ?, ?, ?, ?, ?, ?, ?)", [
            .text(record.requestID.rawValue.uuidString), .text(record.epoch.rawValue.uuidString),
            .text(record.controllerID.rawValue.uuidString), value(record.sessionID?.rawValue.uuidString),
            value(record.runID?.rawValue.uuidString), value(record.kind?.rawValue),
            value(record.digest?.base64EncodedString()), .text(record.disposition.rawValue)
        ])
    }

    private func value(_ string: String?) -> SQLiteValue { string.map(SQLiteValue.text) ?? .null }
    private func corrupt() -> JournalStorageError { JournalStorageError(kind: .invalidState, message: "Invalid journal state") }

    /// Versioned, length-prefixed UTF-8 metadata plus opaque bytes, with no delimiter ambiguity.
    private func fingerprint(_ request: MutationRequest) -> Data {
        var hasher = SHA256()
        func append(_ bytes: Data) {
            var count = UInt64(bytes.count).bigEndian
            withUnsafeBytes(of: &count) { hasher.update(data: Data($0)) }
            hasher.update(data: bytes)
        }
        for field in ["remote-admission-v1", request.epoch.rawValue.uuidString,
                      request.controllerID.rawValue.uuidString, request.requestID.rawValue.uuidString,
                      request.sessionID.rawValue.uuidString, request.runID.rawValue.uuidString, request.kind.rawValue] {
            append(Data(field.utf8))
        }
        append(request.payload)
        return Data(hasher.finalize())
    }
}
