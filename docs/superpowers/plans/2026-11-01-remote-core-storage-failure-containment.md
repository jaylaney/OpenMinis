# Remote Core Storage Failure Containment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox syntax for tracking.

**Goal:** Close the reviewed storage-path gaps, make uncertain SQLite failures fail closed, and complete the missing guard/diagnostic evidence before merging the foundation PR.

**Architecture:** Keep one actor, one prepared journal location and one durable SQLite authority. Resolve only trusted parent aliases, reject unexpected state-file aliases, and retain terminal storage failure independently of cached admission state. No executing host is introduced.

**Tech Stack:** Swift 6, Foundation, system SQLite/Darwin, XCTest; macOS 13 and iOS 16; no external dependencies.

**Spec:** `docs/superpowers/specs/2026-10-30-remote-execution-design.md`, revision 8 and accepted latest review at head `4fd46e2`; this bounded correction updates the contract to the next revision.

## Global Constraints

- No actor suspension between lease/epoch validation and journal reads or mutations.
- Captured epochs must be validated before looking up target runs; keep durable refusals, replay detection, run/session-scoped Stop and recovery behavior.
- Private storage remains below a stable trusted parent. No chmod, unlink, ACL removal or content repair of an existing caller directory or state file.
- A failed rollback must not permit a healthy cached snapshot, further admission, reads of abandoned uncommitted rows, or a new valid lease. Keep both original and rollback diagnostics until the owner is reopened.
- Primary owns staging, commit, push and PR metadata. No merge, public review replies, thread resolution, account/device operations or production app changes.
- All tests/probes use isolated disposable state. No machine memory exhaustion, damaged disks, real data or global production allocator hooks.
- Timeout, explicit close, transport/enrollment, process supervisor, backup/native qualification and optional decode/query cleanup remain deferred.

## Review Focus

- Lock/main-database symlinks, dot-spelled leaves and pre-existing companion files must not redirect storage outside the inspected location.
- Canonical paths and legitimate `/tmp` or `/var` parent aliases must work without resolving away a forbidden state-leaf symlink.
- A failed non-NULL text conversion must never enter the controller first-bind branch; SQL NULL remains distinct.
- After rollback failure, every actor operation including cached status reports the retained storage failure; reopening returns to durable recovery semantics.
- Wrong-session Stop and settled RunID reuse must remain durable policy refusals without altering the target run or becoming generic SQLite failures.

### Task 1: Contain journal paths and terminal SQLite failures

**Files:** Own `src/remote` source/tests/README, plus targeted current-design and original-core-plan contract/evidence updates. May add focused internal path/SQLite-boundary helpers and deterministic test utilities. Primary owns this new plan and ignored execution ledger. Do not change production apps, dependencies, signing or historical review documents.

**Interfaces and decisions:**
- Change `JournalStateDirectory.prepare(_:)` to return the single prepared directory URL or an equivalent internal prepared-path value. Validate the requested leaf spelling before resolving aliases; reject final `.`/`..` and other ambiguous dot path components rather than relying on blind whole-path standardization. Resolve only the trusted parent, append the original valid leaf name, then validate that leaf without following it. All subsequent lock/database operations must use the returned prepared path. Preserve ordinary macOS canonical-parent aliases; do not silently resolve a symlink leaf into its target.
- Open the lock with `O_NOFOLLOW`; open SQLite with `SQLITE_OPEN_NOFOLLOW` as well as its existing flags. Existing state artifacts must be regular files owned by the effective user and have a single hard link, so accidental aliasing cannot bypass exclusive ownership/private storage. Inspect the main database and known SQLite companion paths (`-journal`, `-wal`, `-shm`) before SQLite opens; reject links/nonregular/multiply-linked or foreign-owned artifacts rather than unlinking or repairing them. Check the opened lock descriptor as well. New artifacts remain ordinary private-directory contents. These checks remain cooperative filesystem hygiene under the existing stable-parent boundary, not hostile same-user race isolation.
- In SQLite row mapping, distinguish actual SQLITE_NULL from a nil sqlite3_column_text result for a non-NULL column. The latter throws a captured storage error before any other SQLite API can overwrite its diagnostic. Never return it as an optional nil or allow controller re-binding from it. Retain actual NULL handling for legitimate nullable fields.
- On explicit rollback failure, retain one JournalTransactionError and mark that SQLite owner terminally unusable, even if the native transaction later appears cleared. Every supported operation must surface that stored failure until destruction/reopen. This covers SQL operations, cached status, epoch validation/administrative work, and issuance of new leases; do not leave an active run visible from abandoned uncommitted rows or hide the cause behind a later BEGIN error.
- Public trusted `AdmissionCoordinator.status()` becomes `throws -> AdmissionStatus`; connection status already throws. Update all callers/tests/docs to use try. Keep the existing public error types; a fatal composite must not be unwrapped into a normal AdmissionError refusal. Internal status/health access must make the terminal condition visible without silently changing epochs or releasing authority.
- Use a narrow internal, instance-owned native SQLite boundary or extracted failure-handling seam for deterministic fault tests. It must exercise actual production row/transaction/actor paths, including cached status and unchanged controller binding. No public fault switch, global SQLite allocator replacement, unchecked Sendable shortcut, or test-only production methods. Keep native SQLite as the default. Record simulated failure evidence separately from genuine native OOM/I/O injection, which is not required or claimed here.
- Add meaningful journal regressions for wrong-session Stop against the correct active RunID, and a fresh Start ID reusing a settled RunID. Assert durable rejectedRunUnavailable, unchanged run state/outcome, and replay/reopen persistence where it guards against a realistic regression. Existing guards are correct and should remain.
- Add LocalizedError conformance to AdmissionError with a stable short payload-free message for each current case. Composite diagnostic tests must assert independently meaningful case text, not merely echo whatever localizedDescription returns. Correct the original plan's nonexistent testStopRemainsAvailableDuringRecovery reference to its actual covering test.
- Narrow the documented owner-access check to owner rwx mode bits. Deny-only ACLs can still cause an EACCES filesystem failure when opening storage; this is already fail-closed. Do not add a blanket access() check with mismatched real/effective-UID semantics or broaden native ACL qualification.

- [x] Create regression tests first and record honest RED: actual disposable path escapes; missing readable diagnostics; row failure and terminal-state control-flow tests using the selected internal boundary. API compile RED for throwing status or new seam must be distinguished from runtime failures.
- [x] Implement the bounded changes and run focused GREEN tests. Keep raw SQL NULL behavior and existing real SQLite automatic/ordinary rollback tests passing.
- [x] Test canonical/alias temporary parents, symlink lock/database/companion files, leaf-dot bypasses, ordinary files, unsafe existing artifacts without changes, and valid reopen after releasing ownership. Do not introduce destructive fixture repair outside known temporary directories.
- [x] Test that non-NULL conversion failure cannot change an existing binding; that a failed rollback leaves all actor reads/mutations/status/connect unavailable with both causes; and that no uncommitted run is returned. Verify reopened durable state and recovery without claiming actual native disk failure.
- [x] Update targeted documentation/contracts, run full suite `xcrun swift test --package-path src/remote --scratch-path /private/tmp/openminis-remote-containment-build`, then unsigned generic iOS library compilation with `/private/tmp/openminis-remote-containment-ios-derived`. No native app launch or device registration.
- [x] Inspect actual diff, run whitespace checks and return exact commands/logs, RED/GREEN evidence, test counts, changed files, simulated/native distinction and unresolved concerns. No staging/commit.

### Final review correction: durable DELETE commits

The final whole-branch review identified that synchronous FULL does not request
the extra directory sync after deleting a rollback journal. Select synchronous
EXTRA with DELETE and fullfsync ON, and verify the effective native connection
settings plus ordinary commit/reopen behavior. This addresses the documented
configuration gap; it does not establish native power-loss qualification.

- [x] Effective native durability regression observes the old FULL level before the fix.
- [x] EXTRA configuration correction, full suite and unsigned iOS compile pass.
- [x] Independent scoped re-review approves the complete final fix wave.

## Verification and integration

- [x] Independent task review for conformance and correctness.
- [x] Primary actual-diff inspection and fresh full-package verification.
- [x] Fresh clean-context whole-branch review against base `1a71df0f381cefde80bf912b723de6f9831bc177`.
- Primary commits only reviewed work and updates existing PR #1; no merge or thread resolution.

## Verification result

Primary final verification passed 55 XCTest cases (38 internal and 17 public),
with no failures or compiler warnings. Unsigned generic iOS library compilation
passed after the final source change. Task review approved the containment patch.
The fresh whole-branch review of tree `77426757cac062f1911b908c9bbbbe88a15ab5c6`
identified one Important durability configuration gap; the single fix wave
selected EXTRA, and independent scoped re-review marked it addressed with no
new findings. The effective native setting and ordinary commit/reopen behavior
are verified; real power-loss, native OOM/rollback-I/O and physical-device
qualification are unperformed. All later host/native gates remain pending.
