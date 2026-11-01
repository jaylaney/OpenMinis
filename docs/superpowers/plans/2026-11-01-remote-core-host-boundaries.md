# Remote Core Host Boundaries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox syntax for tracking.

**Goal:** Resolve the three accepted host API/privacy gaps from the updated PR #1 review, with conservative recovery semantics.

**Architecture:** Keep one actor and one exclusive SQLite owner. Expose structured storage failures, scope run reads to storage epochs, validate remote read leases, and require private dedicated storage before opening SQLite. Do not add a host or executing adapter.

**Tech Stack:** Swift 6, Foundation, CryptoKit, system SQLite/Darwin, XCTest; macOS 13 and iOS 16; no new external dependency.

**Spec:** `docs/superpowers/specs/2026-10-30-remote-execution-design.md`, revision 7, plus the accepted updated-review adjudication at commit `90976cb`.

## Global Constraints

- Persist admission before any side effect; identical repeated IDs never authorize another launch.
- Keep lease/epoch validation and journal reads or mutations in the same synchronous actor turn, without an await gap.
- Validate a supplied storage epoch before reading or updating its target run; do not move readStatus above settlement's epoch guard.
- Preserve terminal busy/recovery/absent refusals, run-scoped Stop, actual-recovery lease invalidation, and captured-epoch settlement.
- Only the primary stages, commits, pushes or updates the existing feature PR. No merge, public review replies, account/device actions or production app changes.
- Use only disposable test directories/data; no real documents, Keychain, network peers, user commands or signed app launches.
- Existing async executor, busy-timeout and explicit-close policies, schema/enrollment/revocation, process supervision and optional cleanup remain outside this change.

## Review Focus

- A non-testable client must classify ownership conflicts and SQLite errors without parsing diagnostic strings.
- A failed rollback remains a storage/transaction failure while preserving both causes; do not unwrap it into a benign AdmissionError.
- RunID reuse after reset must not let an old-epoch read observe the replacement run; stale leases must fail on remote reads.
- Bootstrap status must still reveal the current epoch through a valid new connection, while local raw status stays explicitly host-internal.
- An unsafe existing state directory must be rejected before SQLite/lock mutation, without chmod, deletion or changes to its contents.

### Task 1: Implement public errors, scoped reads and private state setup

**Files:** Own `src/remote` source/tests/README and minimal package-manifest changes for a separate public-import test target. May create `JournalErrors.swift` and `JournalStateDirectory.swift` for focused responsibilities. Update current design and initial core plan to reflect accepted API/recovery contracts; do not rewrite historical review documents or change other app code. The primary owns this new plan and the ignored execution ledger.

**Interfaces and decisions:**
- Publish `JournalStorageError: Error, LocalizedError, Sendable` with public `kind`, `message`, optional `sqliteCode`, `sqliteExtendedCode` and `posixCode` fields. Nested public `Kind` cases: `alreadyOwned`, `sqlite`, `filesystem`, `invalidDirectory`, `invalidState`. A value initializer may be public for normal error construction. SQLite codes must come from SQLite while its handle is valid; never classify SQLite or ownership failures by parsing text. Every intentional kernel storage failure should use the appropriate kind. Preserve original diagnostics on automatic rollback.
- Publish `JournalTransactionError: Error, LocalizedError, Sendable` with accessible `originalError` and `rollbackError`. Its localized description retains both diagnostics. It remains distinct from AdmissionError even when the original cause was one. Do not add fault-injection methods to production classes solely for tests.
- Keep `status() -> AdmissionStatus` explicitly trusted host-internal. Add `status(over lease: ConnectionLease) throws -> AdmissionStatus` for connection reads; validate lease/controller but deliberately require no known epoch for bootstrap/reset discovery.
- Replace public unqualified run lookup with `runStatus(for runID: RunID, epoch: StorageEpoch) throws -> RunRecord?` for trusted host callers and add `runStatus(for runID: RunID, epoch: StorageEpoch, over lease: ConnectionLease) throws -> RunRecord?` for connection reads. The second validates both lease and epoch; the first validates epoch. No bare-RunID public lookup remains. Internal journal run lookup also accepts the expected epoch and checks it before querying a run.
- Add `epoch: StorageEpoch` to public `RunRecord`; decode it from the same verified journal namespace as the row. This is a value/API correction, not a persisted schema change. Update status decoding and all existing call sites/tests coherently, keeping settlement's epoch-first property and post-mutation cached-status refresh.
- Require the supplied directory to be a dedicated host state leaf. Create a missing leaf with mode 0700; inspect owner, directory type and permissions before opening the lock or SQLite. Existing leaves must be owned by the effective user, have owner access and no group/other mode permissions, and must not be a symbolic-link leaf. Reject invalid storage with typed invalidDirectory diagnostics. Do not chmod or recursively modify an existing caller directory, its parents or its contents.
- Check extended ACLs rather than treating mode 0700 alone as proof of privacy: reject extended allow entries conservatively, including inherited grants, and fail closed if ACL inspection fails. Deny-only/no-ACL directories may be accepted. Distinguish absent ACL properties through successful native metadata/property queries, not by swallowing ENOENT from an ACL getter. Require populated matching owner/group/mode security properties before accepting absent ACL metadata, so incomplete native retrieval is rejected. Do not remove inherited ACLs silently. Keep the same-user hostile-filesystem exclusion explicit; ordinary POSIX/ACL access checks are not a shell sandbox. Host provisioning must choose a stable trusted parent and explicitly repair any older permissive state directory without losing its journal/epoch.
- Clarify conservative recovery at run level: after restart, a command's exit status does not prove the entire agent run completed. Current confirmation asserts process absence when called and records interruptedUnknown for the interrupted run. Keep the recovery guard; preserve separately observed future tool-level evidence in the later supervisor, and do not imply recovered commands/agent loops resume automatically.

- [x] Write meaningful failing regressions before production changes, with runtime RED for existing observable gaps and honest compile RED for unavailable public API. For permissions, verify new 0700 setup; existing permissive leaf and symlink rejection with no contents/mode changes; accept a private existing leaf; reject an extended allow ACL in a disposable fixture. Do not claim an unrun iOS ACL qualification.
- [x] Add a separate `RemoteExecutionCorePublicAPITests` target using ordinary `import RemoteExecutionCore`, never @testable. Exercise actual public initialization errors (ownership conflict, malformed SQLite, unsafe directory), stable kinds/codes and useful localized diagnostics. Cover composite diagnostic preservation without claiming genuine rollback-I/O injection if only a constructed value is tested.
- [x] Add scoped-read regressions: old epoch after RunID reuse, replaced/reset/recovered stale leases, current valid scoped lookup, RunRecord epoch, and new-lease bootstrap status. Cover epoch-first rejection even when a replacement run cannot be decoded if a focused synthetic fixture is practical.
- [x] Implement the bounded changes and update existing tests and docs. Do not add timeout/close, optional query/decode cleanup or new recovery-completion semantics.
- [x] Run the complete package suite: `xcrun swift test --package-path src/remote --scratch-path /private/tmp/openminis-remote-boundary-build`. Run unsigned generic iOS compilation with `/private/tmp/openminis-remote-boundary-ios-derived`. Record exact logs, warnings and unavailable checks.
- [x] Inspect actual diff, run whitespace checks, and return the full report (commands, RED/GREEN, counts, changed files, residual gates) without staging/committing.

## Verification and integration

- [x] Independent task review for requirements and correctness.
- [x] Primary fresh package verification and actual diff inspection.
- [x] Fresh clean-context whole-branch review against base `1a71df0f381cefde80bf912b723de6f9831bc177`.
- Primary commits only the reviewed correction and updates PR #1 on the existing feature branch; no merge or thread resolution.

## Verification result

Primary fresh verification passed 40 XCTest cases (28 internal and 12 in the
ordinary-import public API target), with no failures or compiler warnings.
Unsigned generic iOS library compilation passed after the final source change.
Independent task and whole-branch reviews found no confirmed findings. The
whole-branch candidate tree was `52d587828d7699479b9b55452c162dab88f62c64`;
subsequent integration edits only record plan progress and clarify fixture
metadata setup in human documentation. Source and tests remain identical.

Native ACL absence handling was checked against Apple's immutable
[statx implementation](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/sys/statx_np.c)
and [filesec implementation](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/gen/filesec.c),
with disposable macOS fixtures. iOS ACL runtime, foreign-UID rejection, genuine
allocation/rollback-I/O failure injection, signed host behavior and physical
qualification remain unproven. The host integration gates remain pending.
