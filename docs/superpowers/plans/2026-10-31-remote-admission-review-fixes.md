# Remote Admission Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox syntax for tracking.

**Goal:** Correct the confirmed admission-core defects from PR #1 and make the remaining host integration obligations explicit.

**Architecture:** Retain one serialized coordinator and durable SQLite authority. Enforce exclusive live ownership before opening SQLite, make submission replay visible to its host adapter, and preserve terminal refusal and error semantics. No executing host is added.

**Tech Stack:** Swift 6, Foundation, CryptoKit, system SQLite and Darwin, XCTest; macOS 13 and iOS 16; no new dependency.

**Spec:** `docs/superpowers/specs/2026-10-30-remote-execution-design.md`, revision 6; PR #1 comments on f1388fd.

## Global Constraints

- Persist admission before any side effect; repeated identical IDs return recorded status, while changed payloads are rejected.
- Persist terminal rejections of valid authenticated requests, including busy responses, as well as admissions.
- Reconnect replaces and fences the previous controller-channel lease before processing requests on its replacement.
- Host-internal completion settlement also carries the storage epoch captured when the run was admitted.
- A fresh storage epoch prevents request replay but does not itself settle surviving processes.
- Existing production apps, transports, credentials, process supervision, enrollment, native UI and physical-device qualification are outside this correction.
- Only the primary stages, commits or pushes. No public replies or thread resolution is authorized by this plan.
- All tests use disposable temporary state, no real app state or Keychain.

## Review Focus

- A recovery refusal must remain refused after confirmation, reconnect and reopen.
- Duplicate Start delivery must give the adapter exactly one fresh-admission result, including across reopen.
- A second owner must fail before mutating state and must not block the first owner's settlement; releasing the owner must allow reopen.
- SQLite automatic rollback must preserve the original storage failure, and explicit rollback of a thrown body error must leave no partial writes.
- No-op recovery confirmation must preserve the current lease; real recovery must still invalidate it.

### Task 1: Repair admission boundary and document host obligations

**Files:** Modify `src/remote/Sources/RemoteExecutionCore/{AdmissionTypes,AdmissionJournal,AdmissionCoordinator,SQLiteDatabase}.swift`, existing journal/coordinator tests and `src/remote/README.md`. May add `JournalDirectoryLock.swift` and `SQLiteDatabaseTests.swift` under their corresponding source/test directories. Update the design and original core plan only to reflect these corrected contracts and clear deferred gates. Do not change production app files or package dependencies.

**Interfaces and decisions:**
- Add public `SubmissionResult: Equatable, Sendable` with `record: RequestRecord` and `isReplay: Bool`; `submit(_:over:)` and internal `record(_:)` return it. Newly inserted records report false; existing records report true, including absence tombstones. Reconciliation still returns RequestRecord. Only `!isReplay && record.disposition == .admitted` signals a new Start admission. This is not evidence of process launch or a durable process-execution claim. Existing admitted records, even on reopen, never authorize launch.
- A new Start during recovery returns a durable `.rejectedBusy` record, because execution remains unavailable while unresolved work holds admission. Reusing the refused ID stays rejected after recovery; explicit later Send uses a new ID. Keep AdmissionError.recoveryRequired for administrative operations where appropriate. No schema change is needed for this disposition.
- Acquire a nonblocking exclusive OS lock for the stable journal directory/database lock file before any SQLite open or mutation, and hold it until the connection closes. Release it on failed initialization and normal destruction. Do not unlink the stable lock file. A concurrent same- or different-controller owner must receive a deterministic failure. Validate the configured controller in the journal initialization transaction before setting recovery; the coordinator supplies it atomically rather than binding after init. Internal journal test setup may be adjusted to make controller ownership explicit.
- Preserve the original transaction error when SQLite already rolled back. Only attempt explicit rollback when sqlite3_get_autocommit says a transaction remains. If that rollback itself fails, retain both original and rollback diagnostics rather than replacing the first or silently swallowing the second.
- `confirmRecoveredProcessesAbsent()` invalidates leases only when recovery actually changed; a no-op leaves the lease usable.
- Clarify automatic Stop retry: never resurrect a tombstoned ID. A definitive rejectedAbsent or another terminally refused Stop requires a new Stop request ID targeting the same epoch/session/run, after checking that target still needs Stop. A changed epoch never silently retargets an old Stop. Receipt of stopRequested does not prove termination.
- Document mandatory host startup process reconciliation before exposing any Start, including fresh/lost/empty storage even when core recoveryRequired is false; absence must be proven or admission remains blocked outside the core. Document backup exclusion as a host-owned pre-service duty, with restore behavior still requiring native qualification.
- Explicitly retain controller replacement/revocation, per-run controller ownership plus schema version/migration planning, and dedicated-executor performance qualification as pre-production host integration gates. Do not suggest deleting the database to replace a phone; no new enrollment API, schema migration or executor is implemented in this bounded fix.

- [x] Write focused regression tests for each confirmed behavioral defect, then run them and record expected RED before changing its production behavior. Runtime failures, not only missing symbols, should establish the bugs where feasible.
- [x] Implement each correction in turn, run its focused regression and record GREEN. Update existing tests to inspect SubmissionResult.record and verify isReplay where it affects launch eligibility.
- [x] Exercise lock contention with same and different controllers, failed initialization cleanup, and successful reopen after release; preserve state, epoch and original lease/settlement. Use deterministic ownership, no sleeps. A raw SQLite full-database fixture must demonstrate the original diagnostic survives automatic rollback.
- [x] Clarify README/design and update the original plan's superseded API/recovery claims. Record deferred host obligations honestly.
- [x] Run the complete package suite with `xcrun swift test --package-path src/remote --scratch-path /private/tmp/openminis-remote-pr1-build`, with compiler access as necessary. Run unsigned generic iOS compilation using isolated `/private/tmp/openminis-remote-pr1-ios-derived`. No signed launch, network peer, device/account registration, or real process command.
- [x] Inspect the diff, run `git diff --check`, and write the implementation report with exact commands, log paths, RED/GREEN evidence, changed files, residual gates and concerns. Leave Git staging/commits to the primary.

## Verification and integration

- [x] Independent task review of the actual diff for specification compliance and correctness.
- [x] Primary inspects changes and runs fresh relevant verification after fixes.
- [x] Fresh clean-context whole-branch review against base `1a71df0f381cefde80bf912b723de6f9831bc177`.
- Primary commits only the reviewed correction and updates the existing feature PR; no merge.

## Verification result

The correction task and independent whole-branch reviews approved the scoped
foundation with no findings. Primary fresh package verification passed 27 XCTest
cases with no failures or compiler warnings; unsigned generic iOS compilation
also succeeded. The complete candidate tree reviewed was
`51bdbff61350daa36f7dc20c1a8b2f20f39e1617`; later edits to this plan only record
verification progress. Cross-process native lock behavior and genuine rollback-I/O
double-failure injection remain unqualified. Host transport, process supervision,
identity lifecycle, backup/restore and physical-device gates remain pending.
