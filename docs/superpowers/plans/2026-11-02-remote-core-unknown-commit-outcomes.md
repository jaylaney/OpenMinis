# Remote core unknown commit outcomes implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Contain an error reported after COMMIT finishes, and enforce reconciliation epochs inside the durable transaction.

**Architecture:** Track body versus COMMIT failure. A failed COMMIT with native autocommit enabled has an unknown outcome and terminally fences the owner until destruction/reopen. Reconciliation independently checks its supplied epoch inside the transaction. Document fresh state-leaf parent persistence as a pending native qualification case.

**Tech Stack:** Swift 6, system SQLite, macOS 13 / iOS 16, XCTest.

**Spec:** `docs/superpowers/specs/2026-10-30-remote-execution-design.md`; accepted PR review disposition from 2026-11-01, authorized by the user's 2026-11-02 instruction to fix them. Findings: PR #1 comments 4436795359, 4436795361, 4436795364, current head `6c63ced318feccbbeaa6f72dba734341f61e8ad8`.

## Global Constraints

- No automatic resend, replay, process launch, epoch reset or fallback after uncertain admission.
- Replay is not launch authority. Retain the ownership lock until connection closure.
- Every API, including cached status, lease issuance and administration, must expose retained terminal storage failure before ordinary admission errors.
- Preserve body-error automatic rollback, successful explicit rollback and existing composite rollback-failure diagnostics.
- Keep DELETE, synchronous EXTRA, fullfsync ON. A simulated reported failure after a real COMMIT is not a genuine VFS, disk or power-loss fault.
- No transport, process supervisor, app integration, provisioning, native power-loss experiment, or changes outside this feature worktree.
- Primary owns documentation, Git operations and final verification. One implementer owns package source/tests. No nested delegation or concurrent shared builds.

## Review Focus

1. Real commit followed by an error must not expose a stale healthy snapshot or permit any more owner operations.
2. Failed reset with a persisted new epoch must not let old leases or epochs write replacement-namespace tombstones.
3. Reconciliation of both existing and absent IDs must reject stale epochs inside its transaction.
4. A COMMIT failure leaving an active transaction must retain the successful-rollback path; body automatic rollback must remain nonterminal.
5. Reopen after unknown Start must preserve the admitted request as replay and require recovery; no second owner may enter while the terminal owner is alive.

### Task 1: Contain unknown COMMIT outcomes and enforce transactional reconciliation epochs

**Files:**
- Modify `src/remote/Sources/RemoteExecutionCore/SQLiteDatabase.swift`, `JournalErrors.swift`, `AdmissionJournal.swift`, `AdmissionCoordinator.swift`.
- Modify/add focused tests under `src/remote/Tests/RemoteExecutionCoreTests` and `RemoteExecutionCorePublicAPITests`.
- Primary updates `src/remote/README.md`, the current design, and this plan's evidence.

**Interfaces:**
- Add public `JournalCommitOutcomeUnknownError: Error, LocalizedError, Sendable` retaining `public let originalError: any Error`; use a diagnostic that explicitly identifies unknown commit outcome and reopening, without fabricating a rollback error.
- Change internal lookup to `lookupOrRejectAbsent(_:epoch:controllerID:)`; pass `epoch` from `AdmissionCoordinator.reconcile` and all internal test callers.
- Retain existing public coordinator signatures and `JournalTransactionError` API.

- [x] **Step 1: Write regressions before implementation.** Extend the instance-owned test native shim to execute real COMMIT successfully and then return a simulated IOERR diagnostic. Cover terminal SQL and all actor APIs after Start/reset; assert original SQLite primary/extended diagnostics; hold ownership until deinit; reopen to verify committed Start/recovery/replay and new reset epoch. Exercise a failed COMMIT with autocommit still disabled and successful rollback. Exercise stale reconciliation for absent and existing records without writing/refetching under the replacement epoch. Verify public ordinary-import diagnostics.
- [x] **Step 2: Record meaningful runtime RED.** Run new behavioral tests against old implementation before introducing new API assertions that cannot compile. Record commands, assertions and log paths. Compilation-only RED is supplementary.
- [x] **Step 3: Implement minimal production changes.** Track when COMMIT is attempted. Failed COMMIT with autocommit enabled stores a distinct unknown-outcome error and fences health. Preserve other rollback paths and error precedence. Verify expected reconciliation epoch within the transaction before lookup/mutation.
- [x] **Step 4: Run focused GREEN and full package suite.** Use `/private/tmp/openminis-remote-unknown-commit-build` and unique fixtures. Source/test edits only; no Git staging/commits from worker. Return report with exact logs, test counts, runtime versus simulated evidence and limitations.
- [x] **Step 5: Primary documentation and independent review.** Document terminal unknown-commit behavior, startup reopen/recovery duties, and the fresh-directory parent-entry power-loss qualification case without claiming directory F_FULLFSYNC is qualified. Run task review then fresh whole-branch review against base `1a71df0f381cefde80bf912b723de6f9831bc177`.
- [x] **Step 6: Primary final verification and PR update.** Run fresh full tests, unsigned generic iOS compilation in separate DerivedData, whitespace check. Commit only authorized changes, push feature branch and update PR description. Do not merge or post review replies.

## Evidence

Completed 2026-11-02. The implementation report and review artifacts are retained in this plan's ignored execution workspace. The final commit and publication state are recorded by Git and PR #1.

- Unknown-outcome runtime RED on unchanged production: four tests, 57 failures, including one cascading staleEpoch error; real COMMIT completed before its simulated reported error. Log: `/private/tmp/openminis-remote-unknown-commit-red.log`.
- Transactional reconciliation runtime RED with only the epoch API migration: two tests, four assertion failures. Log: `/private/tmp/openminis-remote-reconciliation-red.log`.
- Focused GREEN: seven tests. Worker full suite: 62 tests (44 internal +18 public), no failures or warnings. Report distinguishes constructed API tests and simulated reported errors from real SQLite operations.
- Primary fresh full suite: 62 tests, zero failures or compiler warnings. Log: `/private/tmp/openminis-remote-unknown-commit-primary-tests.log`.
- Unsigned generic iOS library compilation: BUILD SUCCEEDED, no warnings/errors. Log: `/private/tmp/openminis-remote-unknown-commit-ios-build.log`.
- Independent task compliance/correctness review and fresh whole-branch review both passed with no confirmed findings. Reviewed candidate tree: `fcb4dc870c674185892126870462d8519687e6ba`; upstream base: `1a71df0f381cefde80bf912b723de6f9831bc177`. Only this completion evidence changed after review. Whitespace checks passed.
- Model routing used supported parent inheritance with high implementation / xhigh review reasoning because the originating model capability ceiling was not concretely exposed; no stronger route was assumed.

Genuine VFS/disk/OOM faults, power loss (including fresh-leaf parent-entry persistence), alternate accounts/filesystems, signed app, iOS ACL runtime and physical-device qualification remain pending. No transport, supervisor or production app was integrated.
