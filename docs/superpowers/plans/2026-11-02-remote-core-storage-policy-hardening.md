# Remote core storage policy checks implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Correct new-state-leaf creation under restrictive umask, verify effective SQLite policy and clarify conservative recovery wording.

**Architecture:** Normalize mode0700 only when this call successfully creates the state leaf; retain all existing leaf/artifact validation. Require actual DELETE and EXTRA values before initializing the journal. Recovery remains interruptedUnknown at whole-run level.

**Tech Stack:** Swift6, Darwin/system SQLite, macOS13/iOS16, XCTest.

**Spec:** `docs/superpowers/specs/2026-10-30-remote-execution-design.md`; accepted PR #1 disposition at `bb0080376fbeadc5c01e7dbc6d9f50319fbd96ec`. User approved recommendations, then explicitly deferred artifact enforcement after discussing its cost.

## Global Constraints

- Normalize only a state leaf created by this call, never an existing or EEXIST object. Never change production process umask or the parent test runner's umask. Preserve existing directory, ACL and artifact refusal without repair.
- Artifact permission enforcement, lock/database precreation or normalization, new private-file helper, compatibility migration, performance and structural refactors are deferred. Preserve current type/effective-owner/link-count/no-follow artifact checks.
- Verify returned journal_mode is DELETE and separately query synchronous to require EXTRA (3) before the schema transaction. Preserve fullfsync ON and foreign_keys ON. Setting verification is defensive policy hardening, not a reproduced silent WAL defect.
- Retain ownership through connection closure and failed initialization, structured diagnostics, terminal-health-first ordering, transactional epochs, replay/refusal and conservative run recovery contracts. No recovery-completed API or automatic execution resumption.
- User scope is this smaller pass. Primary owns docs/Git/final verification; one worker owns package source/tests. No nested delegation, concurrent shared builds, app/transport/device work or cleanup.

## Review Focus

1. New leaf under0177 must become0700 and support the reported coordinator create/reopen scenario. A0777 directory-only fixture may additionally check leaf preparation; do not claim arbitrary-umask artifact support.
2. Run umask tests in an exec-launched isolated child, preserving parent mask and avoiding unsafe Foundation after fork. Existing restrictive/permissive leaves and EEXIST results must not be repaired.
3. Missing/unexpected journal mode or synchronous readback must fail initialization through production checks, retaining native errors and releasing failed initialization ownership. The synchronous setter returns no row.
4. Existing path/ACL/ownership/terminal-error/epoch/recovery tests must remain valid with unchanged artifact contracts.
5. Clarify safe termination/absence of surviving processes, retain separately observed tool evidence, and settle interrupted whole runs as interruptedUnknown.

### Task 1: Correct new-leaf mode and assert effective SQLite policy

**Files:** Modify `src/remote/Sources/RemoteExecutionCore/JournalStateDirectory.swift`, `SQLiteDatabase.swift`; focused tests under existing test directories. Preserve public APIs, lock creation and database creation. Primary owns README/design/plan.

**Interfaces and decisions:** No public API changes. Normalizing only a newly created directory may use the documented stable-parent path boundary when a descriptor cannot be opened under restrictive owner mode bits. Retain subsequent type/owner/mode/ACL validation. Configuration mismatch uses structured JournalStorageError; preserve genuine native error diagnostics. Use existing instance-owned SQLiteNative boundary for mismatch tests if practical.

- [x] **Step1: Write focused regressions and observe runtime RED.** Isolated child exercises new-leaf0177 and directory-only0777 as practical, existing restrictive/permissive leaves remain unchanged. Exercise full coordinator create/reopen under0177. Simulate missing/wrong journal_mode and synchronous results through actual initialization checks. Distinguish native behavior from simulated mismatches. Supplementary compile-only RED is not sufficient.
- [x] **Step2: Implement minimal changes.** New-leaf-only mode normalization; returned DELETE and separate EXTRA readback guards. No artifact enforcement or migration.
- [x] **Step3: Run focused GREEN and full tests.** Dedicated scratch `/private/tmp/openminis-remote-storage-policy-build`, logs `/private/tmp/openminis-remote-storage-policy-*`, unique disposable fixtures. Report exact commands, counts, failures and limits in this plan's `task-1-report.md`; no worker Git operations.
- [x] **Step4: Primary docs and independent reviews.** README/design clarify creation, effective settings and recovery. Task review then fresh whole-branch review against upstream base `1a71df0f381cefde80bf912b723de6f9831bc177`.
- [x] **Step5: Primary integration.** Fresh full tests, unsigned generic iOS library compilation with isolated DerivedData, whitespace checks, feature-branch commit/push and PR description update. No merge, review replies or resolution.

## Evidence

Completed smaller-scope implementation and verification on2026-11-02. Git and PR #1 record final publication state.

- Production change:18 added/changed lines in JournalStateDirectory.swift and SQLiteDatabase.swift. Artifact enforcement, lock/database creation changes, migration and refactors were explicitly deferred by the user.
- Runtime RED on unchanged production: corrected isolated child invocation reproduced0177/0777 new-leaf rejection; wrong/missing settings were accepted and schema created; missing synchronous readback bypassed its simulated native error. Correct delivered-scope log: `/private/tmp/openminis-remote-storage-policy-red-small.log`. Superseded artifact tests and initial runner invocation failures are excluded from this evidence.
- Worker focused/full GREEN and primary fresh full suite:66 discovered(48 internal,18 public),1 intentional parent-only fixture skip,0 failures. Both exec child fixtures completed explicit markers;0177 covers coordinator create/reopen,0777 directory preparation only. Primary log: `/private/tmp/openminis-remote-storage-policy-primary-tests.log`.
- Unsigned generic iOS library compilation: BUILD SUCCEEDED, zero compiler warnings/errors. Log: `/private/tmp/openminis-remote-storage-policy-ios-build.log`. Primary tests also had zero compiler warnings/errors; whitespace checks passed.
- Independent task compliance/correctness review and fresh whole-branch review passed with no confirmed findings. Candidate tree `c38d9d737a2e59a44bd3a14aa222d423ed6c51fb`, upstream base `1a71df0f381cefde80bf912b723de6f9831bc177`. Only this evidence changed after review; source/tests and current design remained frozen.
- Supported parent-model inheritance used high implementation/xhigh review reasoning because the concrete originating model capability ceiling was unavailable. No stronger route assumed.

Wrong/missing setting results and selected errors are deterministic simulations; umask, mkdir/chmod/stat, descriptor opens and0177 coordinator persistence are real macOS runtime operations. No silent WAL-mode defect, genuine VFS/disk/OOM/power-loss behavior, arbitrary-umask artifact support, iOS runtime or physical-device qualification is claimed. Fresh-leaf parent persistence and host integration gates remain pending.
