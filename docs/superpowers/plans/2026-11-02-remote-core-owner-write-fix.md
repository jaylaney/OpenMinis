# Remote core owner-write creation fix implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Prevent a restrictive umask from stranding newly created lock/database files, and verify the fullfsync setting.

**Architecture:** Distinguish exclusive creation from an existing file; normalize owner read/write only for a descriptor newly created by this call. Privately precreate a missing main database while ownership is held, then open it with SQLite. Leave existing file modes and artifact acceptance policy intact. Add the fullfsync readback to existing configuration checks.

**Tech Stack:** Swift6, Darwin/systemSQLite, macOS13/iOS16, XCTest.

**Spec:** `docs/superpowers/specs/2026-10-30-remote-execution-design.md`; accepted PR #1 comments4444113379 and4444113387 at HEAD `0b185d060703c330c1e5a3b3bcc978f7034767b3`; user authorized this concrete recommendation with “k do the fix please”.

## Global Constraints

- Only files successfully created by this call may be normalized. Existing/EEXIST objects must never be chmodded, unlinked, replaced or silently migrated. Existing0644 files remain acceptable; strict artifact privacy enforcement stays deferred.
- Production process umask and parent test runner's umask remain unchanged. New lock/main file owner RW must survive masks removing owner write or read. Use descriptor fchmod after exclusive creation, with no-follow and close-on-exec flags.
- Preserve stable lock inode and nonblocking exclusive flock; hold ownership before production database creation and through SQLite closure, including failed initialization. Retain type/effective-owner/single-link checks and trusted stable-parent boundary. No hostile same-user race-isolation claim.
- A small shared internal creation helper is permitted. SQLite must not silently recreate a missing main file with default permissions after safe precreation. Existing symlink errors may continue to come from native SQLite when appropriate.
- Verify fullfsync readback1 after its setter, in addition to existing DELETE and EXTRA checks. Preserve native errors and schema-before-refusal prohibition. Flag readback is not native F_FULLFSYNC or power-loss qualification.
- No public coordinator API, terminal-error precedence, epoch/lease/replay/refusal/Stop/settlement/recovery changes. No executor/cache/decoding refactors, transport, process supervisor, device/app work or cleanup.
- Primary owns docs/Git/final verification; one worker owns package source/tests. No nested agents or concurrent shared builds.

## Review Focus

1. Under0277, initial creation and actual coordinator close/reopen must retain epoch and allow real writes; previously first creation could succeed but reopening failed.
2. Extend isolated child coverage to masks removing owner read/write, including0777 full coordinator operation if feasible. Children must prove fixture execution; no unsafe work after fork without exec or parent-global mask changes.
3. Existing readable/writable0644 lock/database files remain accepted without mode changes; existing read-only files remain unchanged on refusal, with no automatic repair. Symlink/hard-link checks and stable lock lifetime must remain valid.
4. Missing/wrong fullfsync results refuse initialization before schema work and release ownership; native error codes remain intact. Existing native configuration/commit/reopen evidence remains valid.
5. Exclusive creation, descriptor normalization and closure must preserve single ownership and avoid destructive cleanup after any failure.

### Task 1: Ensure newly created files retain owner RW and check fullfsync

**Files:** Modify `src/remote/Sources/RemoteExecutionCore/JournalDirectoryLock.swift`, `SQLiteDatabase.swift`; add a focused internal creation helper in that source directory if appropriate. Modify existing `StateDirectoryUmaskTests.swift`, `SQLiteStoragePolicyTests.swift`, and focused mode/ownership tests as needed. Primary owns README/design/plan.

**Interfaces:** No public API changes. Internal helper may return a descriptor only for successful O_CREAT|O_EXCL creation; EEXIST returns to ordinary existing-file opening without normalization. Set new-file mode0600 through its descriptor, preserve native errors and close on failure. Main file precreation follows ownership and must not bypass existing no-follow/native-open tests. Other than new-file creation, artifact validation remains unchanged.

- [x] **Step1: Add runtime RED before production edits.** Extend exec-isolated child fixtures to0277 coordinator create/reopen with stable epoch and a real admitted/settled request; add read-bit-removal/0777 cases as practical. Add existing0644 acceptance/mode preservation and existing read-only refusal/no repair coverage. Extend current settings mismatch/missing/native-error cases to fullfsync. Separate real POSIX/SQLite behavior from simulated settings results.
- [x] **Step2: Implement minimal production changes.** New-only descriptor normalization, production main-file creation under ownership, safe SQLite open flags, fullfsync guard. No strict artifact-mode enforcement or migration. Keep failure cleanup non-destructive.
- [x] **Step3: Focused GREEN and full tests.** Scratch `/private/tmp/openminis-remote-owner-write-build`, logs `/private/tmp/openminis-remote-owner-write-*`, unique disposable fixtures. Report exact commands/RED/GREEN/counts and limitations at this plan's `task-1-report.md`. No worker Git mutations.
- [x] **Step4: Primary docs and reviews.** Clarify newly created file RW preservation, existing-state/no-repair policy and all three configuration readbacks. Independent task review and fresh whole-branch review against upstream base `1a71df0f381cefde80bf912b723de6f9831bc177`.
- [x] **Step5: Primary final verification and integration.** Fresh full tests, unsigned generic iOS library compilation with isolated DerivedData, whitespace checks, feature-branch commit/push and PR description update. No merge, PR replies or thread resolution.

## Evidence

Completed implementation and verification on 2026-11-02. Git and PR #1 record publication state.

- Added exclusive new-file creation helper; only newly created descriptors are normalized to 0600. Stable lock acquisition precedes production main-file creation, and SQLite opens without CREATE. Existing 0644 mode/inode acceptance and read-only refusal/no repair remain intact; strict artifact enforcement stays deferred.
- Runtime RED before production edits: 13 selected cases, one fixture-only skip, 13 failures. Owner-write/read-removal masks exposed unusable file modes and reopen failure; missing/wrong fullfsync results bypassed refusal. Log: `/private/tmp/openminis-remote-owner-write-red.log`.
- Focused GREEN: 13 cases, one expected parent-only fixture skip, zero failures. Full worker and primary suites: 69 cases (51 internal,18 public), one expected parent-only fixture skip, zero failures. Five exec child masks (0177,0277,0477,0677,0777) each complete real admission/settlement before and after reopen, stable epoch/lock inode and replay checks. Primary log: `/private/tmp/openminis-remote-owner-write-primary-tests.log`.
- Unsigned generic iOS library compilation: BUILD SUCCEEDED; `/private/tmp/openminis-remote-owner-write-ios-build.log`. Full test and build logs have no compiler warnings/errors; whitespace checks passed.
- Independent task compliance/correctness review and fresh whole-branch review passed with no confirmed actionable findings. Reviewed tree `cc0165891b24e4c79162640f3906473ecad32d4d`, upstream base `1a71df0f381cefde80bf912b723de6f9831bc177`. Only this evidence entry changed after review.
- Supported parent-model inheritance used high implementation/xhigh review reasoning because the exact originating model capability ceiling was unavailable; no stronger route was assumed.

Configuration mismatches and selected native errors are simulated. POSIX permissions, coordinator mutations/reopen and ordinary SQLite are real local macOS operations. Genuine VFS/disk/OOM/power-loss, native F_FULLFSYNC, parent-directory persistence, alternate platforms/accounts and signed/physical host qualification remain pending. No architecture refactors, artifact migration or existing-state repair were performed.
