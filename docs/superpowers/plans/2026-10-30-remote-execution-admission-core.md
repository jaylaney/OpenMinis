# Remote Execution Admission Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Start gate 1 with a portable, durable request-admission and cross-reconnect fencing core that can be tested without exposing a command server.

**Architecture:** A new independent Swift package holds request types and a SQLite admission journal. A single actor owns that journal and controller connection leases, making lease replacement, admission and definitive absence reconciliation linearizable. This increment contains no listener, model calls, shell execution, credentials, or production app wiring.

**Tech Stack:** Swift 6, Foundation, CryptoKit SHA-256, system SQLite, XCTest; deployment floors macOS 13 and iOS 16. No external package dependency.

**Spec:** `docs/superpowers/specs/2026-10-30-remote-execution-design.md`, revision 6; particularly session authority, epochs, busy rejections and reconnect reconciliation.

## Global Constraints

- Existing iOS/Android code, project files, signing configuration, native dependencies, sync and real user data are outside this increment.
- External Tailscale, application authentication, native TLS, process supervision, UI, notifications and physical-device qualification remain later gate 1 work; this package must not advertise them as implemented.
- Every valid mutating request has a storage epoch, controller ID, request ID, session ID, run ID, kind, and payload fingerprint derived internally from canonical metadata plus opaque payload bytes.
- Persist admission or terminal rejection before returning; reusing an ID with different content is rejected. Busy and reconciled-absent dispositions never later become accepted.
- One configured controller and one active run per journal, with enforced nonblocking OS-lock ownership until SQLite closes. Validate/bind the configured controller atomically during initialization before setting recovery. A Stop request records stop-requested, never stopped; only explicit supervisor settlement releases the active slot. Settlement requires the epoch captured at admission; callers must not substitute the current epoch, and an old callback cannot settle a reused RunID after reset.
- Database reopen preserves request dispositions and epoch. Reopening an active run durably rejects new startRun IDs as rejectedBusy until explicit confirmed-absence recovery; those IDs stay refused after recovery; valid run-scoped Stop remains available and only records stopRequested; the core cannot itself verify OS-process absence.
- A fresh database has a new UUID epoch; old epochs are rejected. Reset requires no active/recovery-blocked run, creates a fresh epoch and rejects old namespaces. Host reset/key enrollment behavior is outside this package.
- Lease replacement invalidates the previous controller connection before subsequent operations. No suspension between lease/state validation and the SQLite transaction.
- Definitive no-record reconciliation writes a durable rejection tombstone before returning. An old or delayed submission of that request ID cannot execute afterwards, on any lease or after reopen.
- All fixtures use unique temporary directories. Never access Keychain, CloudKit, home documents, production app databases, network peers or real processes.
- Do not commit, stage, push, publish, register devices or change accounts. Leave changes reviewable in the managed worktree; use uncommitted diff artifacts for review.

## Review Focus

- A delayed old-channel request arriving after an absence lookup must be refused; Task 2 exercises both invalid leases and persistent ID tombstones.
- Same ID with changed run/session/kind/payload must fail, including after reopen; Task 1 covers canonical fingerprints and conflict checks.
- A busy response must remain busy after the active run settles and after reopen; Task 1 tests persisted rejections.
- Stop acknowledgement must not imply a command stopped; Task 1 separates stop-requested from settlement and tests a late Stop against a later run.
- Restart or state loss must not permit old work to be replayed; Task 1 covers fresh epochs and recovery-blocked state, Task 2 tests reconciliation across reopen; the final regression tests delayed settlement after reset and RunID reuse at both journal and actor boundaries.

## File structure and interface contract

Create `src/remote/Package.swift` with library product/target `RemoteExecutionCore`, a system-library target `CSQLite`, and `RemoteExecutionCoreTests`. Keep implementations in focused files under `Sources/RemoteExecutionCore/` and a local `Sources/CSQLite/shim.h`/`module.modulemap` linking sqlite3 through its SDK header. Use Swift 6 language mode.

Public value types live in `AdmissionTypes.swift`: `StorageEpoch`, `ControllerID`, `RequestID`, `SessionID`, `RunID` (UUID-backed Codable/Hashable/Sendable wrappers with `init(rawValue: UUID = UUID())`); `MutationRequest` (epoch, controllerID, requestID, sessionID, runID, `MutationKind`, payload Data); `MutationKind` (`startRun`, `stopRun`); `RequestDisposition` (`admitted`, `stopRequested`, `rejectedBusy`, `rejectedAbsent`, `rejectedRunUnavailable`); `RequestRecord` (identity metadata, optional digest, disposition); `SubmissionResult` (record: RequestRecord, isReplay: Bool); `RunOutcome` (`completed`, `failed`, `interruptedUnknown`); typed `AdmissionError` for stale epoch, payload conflict, recovery required, invalid transition, wrong controller and stale connection. Add public `RunState` (`active`, `stopRequested`, `settled`) and `RunRecord` with session/run IDs, state and optional outcome, and `AdmissionStatus` with epoch, recoveryRequired and optional active run. RequestRecord session/run/kind fields are optional for an unknown-ID rejection tombstone; its request/controller/epoch fields are always present. Do not include payload contents in descriptions/logs. A rejection tombstone may have no digest and must reject any later content for the same request ID. RequestRecord represents admission/rejection, not proof that a run or command finished; use runStatus for settled outcomes. SubmissionResult.isReplay is false only on insertion and true for every existing record, including absence tombstones. Only a non-replay admitted result signals new Start admission; it is not a durable process-launch claim, and replay never authorizes launch.

Internal `AdmissionJournal` owns one SQLite connection and offers synchronous methods: `init(directory: URL, controllerID: ControllerID) throws`; `epoch: StorageEpoch`; `recoveryRequired: Bool`; `status: AdmissionStatus`; `runStatus(for runID: RunID) throws -> RunRecord?`; `record(_ request: MutationRequest) throws -> SubmissionResult`; `lookupOrRejectAbsent(_ requestID: RequestID, controllerID: ControllerID) throws -> RequestRecord`; `settle(runID: RunID, epoch: StorageEpoch, outcome: RunOutcome) throws`; `confirmRecoveredProcessesAbsent() throws`; `reset() throws -> StorageEpoch`. Use transactions and a unique request key; no application logic outside these methods can update journal tables. Expose the journal internally for @testable tests, not as an independent public server API.

Task 2 produces public `AdmissionCoordinator` actor. It creates/owns the journal from directory and configured controller ID, binds/validates that controller durably before initialization succeeds, and rejects a mismatched existing journal binding. Public API: `connect(controllerID:) throws -> ConnectionLease`; `submit(_:over:) throws -> SubmissionResult`; `reconcile(requestID:epoch:over:) throws -> RequestRecord`; `status() -> AdmissionStatus`; `runStatus(for runID: RunID) throws -> RunRecord?`; `settle(runID:epoch:outcome:) throws`; `confirmRecoveredProcessesAbsent() throws`; `reset() throws -> StorageEpoch`. `ConnectionLease` is an unforgeable-by-initializer public value with private token/controller fields, constructed only by this actor. Coordinator validates configured controller, token and epoch before entering journal methods. Administrative settlement/recovery/reset are host-internal integration APIs; none is exposed over a network in this increment. Document that an external authenticated host adapter must supply the configured controller, verify process absence and serve these methods; this core does not authenticate people or supervise processes.

### Task 1: Durable SQLite admission journal and state model

**Files:** Create the manifest, CSQLite shim/module map, AdmissionTypes.swift, AdmissionJournal.swift and focused SQLite helpers if needed; create journal tests under `Tests/RemoteExecutionCoreTests/`.

**Interfaces:** Consumes platform SDK SQLite/CryptoKit only. Produces the exact synchronous journal contract above for Task 2. The implementer may refine names only after notifying the primary and updating this plan before dependent work starts.

- [x] Write meaningful failing XCTest cases before production code: `testAcceptedRequestSurvivesReopen`, `testChangedPayloadOrMetadataConflicts`, `testBusyRejectionSurvivesIdleAndReopen`, `testStopWaitsForSettlementAndDoesNotStopLaterRun`, `testReopenWithActiveRunRequiresRecovery`, `testStopRemainsAvailableDuringRecovery`, `testUnknownRequestBecomesPermanentRejection`, `testResetAndFreshDirectoryRejectOldEpoch`.
- [x] Run the focused tests and record the expected missing-behavior failure. Creating the manifest and an empty module is permitted for this red cycle; do not implement behavior first.
- [x] Implement metadata/fingerprint validation, durable SQLite transactions and journal operations. Use full durability and foreign/unique constraints, close/finalize resources reliably, propagate storage errors, and avoid unchecked Sendable or swallowed exceptions. Persist the first configured/valid controller binding and retain it across storage reset; wrong controllers cannot record or reconcile. `startRun` reserves the only active slot; busy requests persist rejected. `stopRun` applies only to its exact active run/session; a late stop is rejected and cannot act on a later run. `settle` is explicit and idempotent for the same terminal outcome, rejecting contradictory settlement. On reopen unresolved active work requires recovery, which settles it interrupted-unknown only after the host's explicit confirmation of process absence. Reset is refused until work is settled.
- [x] Run `swift test --package-path src/remote --scratch-path /private/tmp/openminis-remote-admission-build` and record the complete package result. Inspect the actual diff and write a report; no commits.

### Task 2: Serialized controller leases and definitive reconnect reconciliation

**Files:** Create `AdmissionCoordinator.swift`, coordinator/reconnect tests, and `src/remote/README.md`. Modify Task 1 types for the agreed status/lease contract and pass the configured controller into atomic journal initialization; do not weaken journal semantics to make tests pass.

**Interfaces:** Consumes the journal and types from Task 1. Produces the public actor/status/lease API above. Return typed wrong-controller or stale-lease errors without creating journal records for unauthorized operations.

- [x] Write failing tests: `testReplacingLeaseFencesDelayedOriginal`, `testAbsentLookupTombstonesRequestBeforeNewSend`, `testTombstoneSurvivesReconnectAndReopen`, `testWrongControllerCannotConnectOrMutate`, `testConfiguredControllerMustMatchPersistedBinding`, `testStaleEpochCannotSubmitOrReconcile`, `testStopAndSettlementRemainRunScoped`, `testRecoveryAndResetInvalidateOldLeases`.
- [x] Run focused tests and record failure before implementing the actor.
- [x] Implement the actor with synchronous journal calls after validation; no await/reentrancy gap between lease validation and commit. `connect` invalidates the old lease before returning the new one; a rejected foreign-controller connect must leave the valid current lease intact. `reconcile` validates epoch/lease and atomically returns an existing record or stores rejectedAbsent. `submit` never resurrects a terminal rejection. Reset and actual recovery changes invalidate prior leases; no-op recovery preserves them. Include deterministic ordered-concurrency tests where the old submit is released only after replacement and absence reconciliation.
- [x] Document package purpose, test command, status semantics, trust/process-adapter preconditions, and remaining native TLS/transport/supervisor/UI gates. There is no runnable host yet and no production app integration.
- [x] Run the complete package suite and compile the package for generic iOS without signing if a reproducible local package build command is available. Record exact commands and any unavailable check; no device registration or native-app launch.

## Verification and handoff

- [x] Independent spec/correctness review of each task's actual uncommitted diff; fix confirmed important issues with the implementer and review the changed clauses/code again.
- [x] Primary runs a fresh full package test suite and `git diff --check` after integration.
- [x] Fresh whole-increment read-only review of all changes against the spec/plan, including adversarial admission and recovery scenarios.
- [x] Report code/tests separately from native/physical evidence. This increment starts implementation; it does not pass gate 1, and gate 2 production extraction remains pending the signed/native transport and process-supervision qualification.

No implementation beyond these two tasks is part of this initial plan. The next bounded plan builds the authenticated native connection and supervised scripted-tool host on this reviewed core, then the standalone iOS qualification screen. User authorization to start is already present; no additional confirmation is needed for this plan's reversible work.

## Original execution result (before PR corrections)

Completed the two-task initial increment plus the final review correction: settlement now requires its captured storage epoch. Final primary package suite: 18 tests, zero failures. Unsigned generic iOS package compilation succeeded. Independent task reviews approved both tasks; whole-increment review found one P2 that was fixed with runtime RED/GREEN regressions and verified by a scoped re-review. No commits, native host, app integration, signed launch, live Tailscale connection or physical-device acceptance is claimed.

## PR correction contracts and deferred integration gates

The follow-up review correction updates the original API and recovery claims above:
submission returns a replay marker, recovery refusal is permanent, journal ownership
is enforced before SQLite opens, wrong-controller initialization cannot change
recovery, and transaction failures retain their original diagnostic even when
SQLite has already rolled back. The correction report records fresh verification.

The host must prove managed-process absence on every startup before exposing
Start, including fresh/lost/empty storage even when core recoveryRequired is false.
Backup exclusion must be applied and verified by the host before service; native
restore qualification remains pending. Automatic Stop retry must use a new ID
after a definitive terminal refusal, retain the exact epoch/session/run target,
and never interpret stopRequested as termination. A changed epoch cannot silently
retarget an old Stop.

Controller replacement/revocation, per-run controller ownership, schema version
and migration planning, and dedicated-executor performance qualification remain
pre-production host gates. No enrollment/revocation API, schema migration or
dedicated executor is implemented by this correction; database deletion is not a
controller replacement procedure. The replay marker does not implement durable
process-launch ownership or the later native launch/recovery protocol.
