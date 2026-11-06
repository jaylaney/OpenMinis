# PR #7 authenticated-status fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the four confirmed PR #7 behavior issues without broadening Gate A.

**Architecture:** Separate the existing serial owner's local policy lifetime from listener activation. Carry the owner's enrollment phase/resource presence to UI and return known committed confirmation separately from ACK delivery. One implementer owns the coupled fix wave; one fresh independent whole-branch gate covers its contracts together.

**Tech Stack:** Existing Swift 6 package, SQLite, SwiftUI/Combine, Network/Security; macOS 13/iOS 16; existing exact dependency pins.

**Spec:** [authenticated-status contract revision 3](../specs/2026-11-02-remote-execution-prototype-design.md), especially Approved PR #7 corrections. User approved these four fixes on 2026-11-04 following read-only triage; continue using subagents. No additional permission gate for routine implementation choices within those corrections.

## Global Constraints

- One store/lock/serial owner for prototype SQLite, policy, pending enrollment and leases; no second allowlist or raw-handle escape.
- Storage failure synchronously fences transport and retains the original error/owner/lock until explicit close. Never silently reopen/reset/retry a published failed owner.
- Only authenticated status is a controller RPC. No execution/helper/Stop/reset/replacement/provider/session/production integration.
- Core owns expiry and authorization. Preserve immutable claims, accepted-digest gating, post-send candidate publication, operation/incarnation guards and immediate cancellation.
- No wire/schema/dependency/OS-floor changes. Phone graph remains controller model/Wire/Transport only.
- Only disposable tests and signing-disabled builds; no real Keychain, device/app launch, signing/account/profile/tailnet/firewall actions.
- Primary owns staging, commits, push and PR metadata. Workers never mutate Git state or send PR comments. Keep temporary records; no cleanup of user state.

## Review Focus

1. Offline policy load must invoke no certificate/listener route and cannot fresh-create or silently reopen a terminal owner.
2. Late local-open completion after Close/Enable cannot publish stale handles or leave an unreachable lock.
3. Commit-first plus lost send is known committed; disconnect-first, failed COMMIT and unknown COMMIT are not falsely reported committed.
4. A post-commit readiness failure must remain visible without erasing known commit or restoring transport authority.
5. Candidate-fixed/send-held phase must keep Open enrollment disabled and must still publish the local comparison after send completion.

## Task 1: Coupled Core/Host/model correction wave

**Modify:**
- `src/remote/Sources/RemoteExecutionCore/StatusOnlyTypes.swift`: `StatusOnlyHostConfiguration.allowsFreshStore: Bool`, initializer default `true`.
- `src/remote/Sources/RemoteExecutionCore/JournalStateDirectory.swift`: `prepare(_:createIfMissing: Bool = true)`; default legacy behavior unchanged.
- `src/remote/Sources/RemoteExecutionCore/StatusOnlyJournal.swift`: honor existing-only open before fresh identity/DB creation, pass directory creation flag.
- `src/remote/Sources/RemoteExecutionCore/StatusOnlyHost.swift` and `StatusEnrollment.swift`: the public facade becomes `@discardableResult confirmCandidate(candidateID:) async throws -> StatusOnlySnapshot`; the internal owner-state method remains synchronous and returns the journal-confirm snapshot after COMMIT.
- `src/remote/Sources/RemotePrototypeHost/HostService.swift`: `openLocalPolicy(configuration:) async throws`, no TLS/listener work; existing-only owner and generation-safe cleanup. Existing Enable remains explicit network activation; preserve config flags through wrappers.
- `src/remote/Sources/RemotePrototypeHost/HostRPCDispatcher.swift`: add `HostConfirmationOutcome` with `case committed(acknowledgementSent: Bool)`; return it from confirmation after successful Core commit. Use returned committed snapshot for ACK rather than another post-commit policy read. Add resource/enrollment presentation fields, preserve candidate notification.
- `src/remote/Sources/RemoteHostPrototypeModel/HostModel.swift`: extend service adapter for explicit local load and confirmation outcome. Add `loadLocalPolicy()` user action, `hasOpenOwner`, `canClose`, actual owner enrollment phase and committed notice. Revoke gating uses enrolled local policy independently of hosting; automatic refresh never opens owners. Enrollment gating includes pending candidate phase.
- `src/remote/prototype/MacHost/HostView.swift`: use explicit local load/refresh action and independent Close availability; render committed notice separately from readiness error. No launch or window-lifetime activation changes.

**Tests:** Existing relevant Core schema/owner/enrollment tests, HostBridgeTests/fixtures and HostModelTests. Add files only for a focused fixture if needed; no public bypass seam.

**Interfaces:** Preserve existing callers with defaulted config/presentation additions where sensible. Host confirmation is a local committed result, not proof of phone persistence/receipt. Core returning a snapshot grants no extra remote capability. The same selected installation is used for local policy and network hosting. Explicit local load must refuse/require close when a published failed owner remains; never hide failure by replacing it. It may reuse an existing healthy owner for a local refresh without enabling networking.

- [ ] Write failing existing-only tests: `testExistingOnlyOpenRefusesFreshWithoutCreation` asserts missing leaf stays absent, zero-byte main unchanged, no identity resolver/random calls, no new policy; `testExistingOnlyOpenLoadsEnrolledPolicy` asserts same IDs/generation/pin through real Core reopen.
- [ ] Run those focused Core tests, capture expected failures, then implement defaulted flag/directory handling and rerun GREEN. Preserve all legacy directory and policy behavior.
- [ ] Write failing Host/Model tests: offline enrolled load/revoke with zero TLS-key/certificate/listener calls, retained close after revoke/storage failure, close during held local-open completion. Assert real lock retained before close and acquirable afterward; revoked policy survives reopen.
- [ ] Implement `openLocalPolicy` and model/view lifecycle controls with bounded generation guards; run focused Host/Model tests GREEN.
- [ ] Update lost-ACK regression to assert `.committed(acknowledgementSent: false)` and successful normal reconnect; add held commit/disconnect, commit-error/unknown outcome and post-commit readiness-failure assertions as needed. Confirm failing behavior before implementation.
- [ ] Implement committed snapshot/result propagation; keep Core failure outside delivery handling, catch only post-known-commit delivery/liveness failures as uncertain ACK. Preserve synchronous fences and surface later storage readiness error.
- [ ] Add Open enrollment gate tests for owner `.open`, `.candidate` with no visible candidate/send held, displayed candidate, and `.closed` after expiry. Assert repeated clicks do not submit a second open and send completion still publishes candidate. Implement the authoritative phase/poll gate and rerun GREEN.
- [ ] Run `xcrun swift test --package-path src/remote --scratch-path /private/tmp/openminis-status-package --filter 'StatusSchemaTests|StatusOwnerTests|StatusEnrollmentTests|HostBridgeTests|HostModelTests'`; expect exit 0 and zero failures. Report exact RED/GREEN commands/logs and changed files. Primary performs full combined verification.

## Task 2: Primary integration, review, qualification and PR update

- [ ] Inspect actual diff and regression evidence; make one review package including tracked/untracked files against fork baseline `fcb9bb8f57cfd7241c01e22bdd87769f91364e7d`, plus the fix-only diff from `0487fcdd1aac3668fcafb650968d38fca7cb8c2a`.
- [ ] Dispatch a fresh clean-context, read-only whole-branch reviewer against current revision 3 contract. This gate assesses the one coupled fix wave and its interactions; no duplicate task-only review. Inherit parent model because originating capability ceiling is unidentified; implementer high, adversarial reviewer xhigh; no nested delegation.
- [ ] Run full `xcrun swift test --package-path src/remote --scratch-path /private/tmp/openminis-status-package`, then both existing standalone xcodebuild schemes with `CODE_SIGNING_ALLOWED=NO`, serialized, same disposable scratch/DerivedData paths. Expected exit 0; inspect counts, warnings and actual artifact graph/hashes. No launch.
- [ ] Update README/QUALIFICATION for current source fingerprint, tests, builds, review chain, artifact hashes and unchanged physical gates. Only relevant checks; final diff/link/whitespace and fingerprint checks.
- [ ] Resolve any blocking review issue through implementer fix plus independent scoped re-review. Once clean, stage the scoped changes, commit on the existing PR branch and push to the user's fork. Refresh PR description/evidence as needed; no merge, PR replies, thread resolution or issue closure.
