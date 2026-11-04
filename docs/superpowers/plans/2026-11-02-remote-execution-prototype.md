# Authenticated-status implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans after explicit implementation authorization. Steps use checkbox syntax for tracking.

**Goal:** Build separate foreground Mac/iPhone prototypes that enroll one controller, authenticate, read committed status, reconnect and revoke locally, with commands unavailable.

**Architecture:** Add a minimal status profile inside RemoteExecutionCore using its existing file/transaction kernel and a dedicated serial owner. Wire/Transport expose no Core authority; a Mac-only bridge translates verified channel proofs into narrow owner calls. Separate unsigned app targets exercise this boundary without production integration.

**Tech Stack:** Swift 6, macOS 13/iOS 16 floors, Foundation/Dispatch/CryptoKit/Network/Security/system SQLite; exact candidate X509 1.17.0 in a Mac-only certificate target.

**Revision:** 2 — 2026-11-03 review corrections; documentation only.

**Spec:** [authenticated-status design](../specs/2026-11-02-remote-execution-prototype-design.md), [parent design, revision 12](../specs/2026-10-30-remote-execution-design.md). Baseline `fcb9bb8f57cfd7241c01e22bdd87769f91364e7d`. Read both; the status design supersedes the earlier scripted proposal.

## Global constraints

- Documentation only now. Implementation and disposable automated checks require a subsequent explicit request; signed/physical work requires a separate bounded manifest/request. No automatic commits, signing, installs, dependency resolution, Keychain writes, device/Tailscale/privacy actions or publication.
- Preserve the historical 69-case legacy foundation contracts. No package-wide executor rewrite; retain the legacy actor and explicitly blocking synchronous initializer. Prototype UI uses only the async factory.
- One private leaf, stable `admission.lock`, `admission.sqlite3`, serial owner, incarnation and policy authority. No AdmissionJournal/AdmissionCoordinator instance, parallel database, second allowlist, raw SQLite escape or legacy RPC forwarding in the prototype.
- Status application ID `1330467668` (`0x4f4d5354`), version `1`, exactly the design's `prototype_status` DDL. Copy that DDL byte-for-byte as the single production constant; no SQL normalizer or schema invention. No migration/reset/recovery/copy preflight/companion cleanup.
- Unsupported original bytes, modes, inodes, epoch and bindings stay unchanged; a previously absent ownership lock may be created. Missing/zero-byte main without forbidden entries is fresh; the exact validated `.DS_Store` exception is non-authoritative metadata. Existing artifact permissions are not repaired; existing writable 0644 remains compatible with legacy rules.
- Continuous monotonic nanoseconds; checked deadline addition; equality expires. Authentication deadline is trusted acceptance time + `10_000_000_000`; enrollment window `120_000_000_000`. Two non-authenticated sockets, five failed enrollment proofs, one outstanding request, one queued frame (`N <= 4096`, ≤4100 bytes including prefix) and ten-second send deadline.
- TLS 1.3; ALPN `openminis-prototype/1`; no early data/resumption. Exact selected existing `100.64.0.0/10` IPv4, port `1024...65535` (default `49152`), no fallback. P256 full canonical SPKI pin and contextual exporter are mandatory.
- Unsigned bundle IDs `org.openminis.prototype.host` / `org.openminis.prototype.controller`; verify team availability before registration/signing, without asserting DNS ownership. Keychain services `org.openminis.prototype.host.identity.v1`, `org.openminis.prototype.controller.identity.v1`, `org.openminis.prototype.controller.hostpins.v1`; after-first-unlock, this-device-only, explicitly non-synchronizable; all Mac SecItem operations select `kSecUseDataProtectionKeychain = true`, with no file-Keychain fallback or replacement on read failure. Signed default access groups and profiles remain the physical gate.
- No helper/script/Stop/approval/event/output/process/provider/sync route or production `src/ios`/project/data changes. Every app screen states “Commands unavailable.” StatusResponse is epoch plus constant zero execution capability, never AdmissionStatus/recoveryRequired.
- Primary owns Git and integration. Task completion supplies a reviewable diff; commits require separate instruction and are primary-only. Serialize shared build outputs; use disposable fixture directories and isolated scratch/DerivedData paths.

## Review focus

1. A clean-looking OMST database accompanied by an empty journal or unknown super-journal must remain byte-identical (Task 1).
2. A valid proof arriving before ten seconds but queued until deadline must fail without replacing the current lease (Tasks 4–5).
3. A racing claimant must not select its key against a previously disclosed SAS nonce or make another phone display a code (Tasks 4, 7, 12).
4. A revocation followed by a failed commit and late queued status response must never re-enable transport or claim durable success (Tasks 5, 11).
5. Lost EnrollmentCommitted followed by reconnect must preserve the phone key and tentative pin without replaying enrollment or overwriting an existing paired pin (Tasks 11–12).

## File and interface map

All package paths below are relative to `src/remote`; `Core` means `Sources/RemoteExecutionCore`. App paths are relative to `src/remote/prototype`.

| Responsibility | Create/modify |
| --- | --- |
| Clean opening/schema | Core `StatusStorePreflight.swift`, `StatusReadOnlyDatabase.swift`, `StatusSchema.swift`, `StatusOnlyJournal.swift`; modify `AdmissionJournal.swift` only for pre-writable OMST guard; reuse `JournalStateDirectory`, `JournalDirectoryLock`, `SQLiteDatabase`, `SQLiteNative` |
| Serial authority | Core `StatusOnlyTypes.swift`, `StatusOnlyHost.swift`, `StatusOnlyOwner.swift`; no networking imports |
| Public wire values | `Sources/RemotePrototypeWire/{Frames,Messages,Invitation,AuthTranscript}.swift` |
| Native adapters | `Sources/RemotePrototypeTransport/{PrototypeKeyStore,PinnedTLS,StatusTLSChannel,ConnectionPump,PeerAuthentication}.swift` |
| Certificate | `Sources/RemotePrototypeCertificates/HostCertificate.swift` |
| Trusted bridge | `Sources/RemotePrototypeHost/{HostService,HostRPCDispatcher,ServiceFence}.swift` |
| App models | `Sources/RemoteHostPrototypeModel/{HostModel,PrototypeInstallationSelection}.swift` (Mac-only, RemotePrototypeHost dependency); `Sources/RemoteControllerProbeModel/ProbeModel.swift` (Wire/Transport dependencies only) |
| Standalone UI | `RemoteExecutionPrototype.xcodeproj`, `MacHost/{App,HostView}.swift`, `iOSProbe/{App,ProbeView}.swift`, `QUALIFICATION.md`; each app imports its model product |
| Tests/package | Existing Core test targets plus `RemotePrototypeWireTests`, `RemotePrototypeTransportTests`, `RemotePrototypeHostTests`, `RemoteHostPrototypeModelTests`, `RemoteControllerProbeModelTests`; `Package.swift`, isolated resolved graph |

Integration names below are concrete proposed implementation choices, not deferred design decisions. `StatusClock.nowNanoseconds() -> UInt64`; `StatusRandomSource.bytes(count: Int) throws -> Data`. `StatusOnlyHostConfiguration` fields: `directory: URL`, `clock: any StatusClock`, `random: any StatusRandomSource`, `identityResolver: @Sendable (Data?) throws -> Data`, `onUnavailable: @Sendable () -> Void`. Protocols are Sendable; resolver and cancellation-only failure callback execute synchronously on the owner queue. onUnavailable cannot reenter Core; original errors remain owner-retained, never callback payloads. Internal test injection supplies instance-owned SQLiteNative, backup-exclusion backend and deterministic queue barriers, absent from the public API.

New status IDs use UUID, separate from legacy ID wrappers. `StatusHandshakeMode: UInt8` cases `.enrollment = 1`, `.normal = 2`. `StatusHandshakeInput` fields: `connectionID: UUID`, `acceptedAtNanoseconds: UInt64`, `mode: StatusHandshakeMode`, `hostID: UUID`, `hostPin: Data`, `controllerSPKI: Data`, `clientNonce: Data`, `invitationID: UUID`. `StatusHandshakeContext` fields: `contextID: UUID`, `serverNonce: Data`, `controllerID: UUID`, `generation: UInt64`, `invitationSecret: Data?` (trusted bridge only). `StatusEnrollmentWindow`: `hostID`, `hostPin`, `invitationID`, `secret: Data`, `deadlineNanoseconds: UInt64`. `StatusAcceptedCandidate`: `candidateID`, `connectionID`, `claimDigest: Data`, `sasNonce: Data`. UUID field types remain UUID throughout.

`StatusOnlySnapshot`: `hostID`, `storageEpoch: UUID`, `controllerID`, `controllerGeneration: UInt64`, `executionCapability: StatusExecutionCapability` (`.unsupported` only). `StatusOnlyLocalSnapshot`: `snapshot`, `controllerState: StatusControllerState`, `enrollment: StatusEnrollmentState`, `readiness: StatusReadiness` (`.available`; unavailable operations throw). Controller state raw strings are exactly `unenrolled/enrolled/revoked`; enrollment is closed/open/candidate. `StatusControllerLease` has internal-only construction, no Codable/wire form, and captures owner incarnation, connection token/ID, epoch and generation.

Tasks 1–12 use a checked test cycle: write named failing tests, run RED, implement the exact interfaces, run GREEN. Larger UI tasks separate their implementation actions. Task 13 records combined verification/review evidence without an artificial failing documentation test. `T` below means the literal command prefix `xcrun swift test --package-path src/remote --scratch-path /private/tmp/openminis-status-package`; append the shown `--filter`. Missing APIs/types are acceptable RED compilation failures; an empty test selection is never success. Commands are instructions for later authorized execution, not results.

### Task 1: Untouched clean-store preflight and legacy namespace guard

**Files:** Create Core `StatusStorePreflight.swift`; modify `AdmissionJournal.swift` immediately after lock acquisition/before SQLiteDatabase construction. Test `Tests/RemoteExecutionCoreTests/StatusPreflightTests.swift`.

**Interfaces:** Internal `StatusStorePreflight.inspectOwned(directory: URL) throws -> StatusStoreProbe` and `recheck(_ probe: StatusStoreProbe) throws`; probe retains fresh/existing classification, inode/device/size/content digest and directory inventory. `refuseStatusNamespaceForLegacy(directory: URL) throws` reads only the no-follow main header under the existing lock.

- [ ] Write `testFinderMetadataIsIgnoredSafely`: permit only regular/euid-owned/single-link `.DS_Store`, leave its bytes/mode/inode unchanged, and tolerate its valid appearance/disappearance during recheck; symlink/nonregular/foreign-owned/multiply-linked variants refuse without traversal. `testMetadataDoesNotHideRecoveryState`: metadata plus any journal/WAL/unknown entry still refuses all original bytes unchanged. `testCompanionsAndForeignHeadersStayUntouched`: assert unchanged bytes/modes/inodes for empty/nonempty journal/WAL/SHM, super-journal/unknown files, foreign/unversioned/truncated/WAL-format headers; canary referenced outside leaf unchanged. `testOwnershipAndLegacyGuard`: same lock excludes both profiles; legacy refuses OMST after status-profile lock release; zero-byte/no-companion is fresh; safe legacy fixtures still open. Build OMST fixtures directly using existing CSQLite, the frozen DDL/header and stable lock, without the future StatusOnlyHost factory.
- [ ] RED: `T --filter StatusPreflightTests`; expect missing preflight/guard or preservation assertion failure.
- [ ] Implement directory prepare → stable lock → complete inventory → no-follow header inspection. Permit only lock/main plus the exact validated `.DS_Store` exception; ignore its contents and exclude it from authoritative inventory comparisons while rechecking its type/ownership/link count if present. Verify SQLite magic, offsets 18/19=`1/1`, application ID at 68 and version at 60. No SQLite open for unsupported input; preserve legacy behavior except OMST refusal.
- [ ] GREEN: same command; all fixtures pass, including symlink/hardlink/euid/private-leaf checks and no lock replacement.

### Task 2: Exact schema, read-only validation and identity agreement

**Files:** Create Core `StatusOnlyTypes.swift`, `StatusReadOnlyDatabase.swift`, `StatusSchema.swift`, `StatusOnlyJournal.swift`; test `Tests/RemoteExecutionCoreTests/StatusSchemaTests.swift`. Define the shared configuration/clock/random/value types from the interface map here; Task 3 adds handles.

**Interfaces:** Internal read-only connection uses `SQLITE_OPEN_READONLY|FULLMUTEX|NOFOLLOW`, no CREATE. `StatusSchema.validate(read: (String) throws -> [[String?]]) throws -> StatusStoredPolicy`; `StatusOnlyJournal.open(configuration: StatusOnlyHostConfiguration, native: any SQLiteNative, backupExclusion: any StatusBackupExclusion) throws -> StatusOnlyJournal` prepares/acquires/retains its stable lock and uses Task 1 preflight itself. Journal `readPolicy() throws -> StatusStoredPolicy`, `confirm(key: Data) throws -> StatusStoredPolicy`, `revoke() throws -> StatusStoredPolicy`, `checkHealth() throws`. Stored policy contains snapshot fields plus `controllerState: StatusControllerState`, `controllerSPKI: Data?`, `hostPin: Data`. Internal protocol `StatusBackupExclusion` requires `applyAndVerify(_ directory: URL) throws`; production uses Foundation's isExcludedFromBackup set/readback, tests inject an instance-owned implementation.

- [ ] Write `testExactReferenceSchemaAndData`: compare stored SQL/implicit indexes to the frozen DDL instantiated in memory; reject extra tables/views/triggers/user indexes, reordered/wrong implicit indexes, malformed UUIDs/keys/digests, rows other than singleton and integrity output other than sole `ok`. `testFreshAndExistingIdentity`: fresh resolver receives nil once; existing receives saved pin; missing/mismatch refuses before writable open without rotation. `testValidatorNeverWrites` checks bytes/companions and recheck failure on changed identity/content. `testBackupExclusionBeforeReadiness` asserts injected set/readback success precedes journal return and errors block readiness.
- [ ] RED: `T --filter StatusSchemaTests`; expect missing validator/journal.
- [ ] Implement fresh transaction setting ID/version/table/one row together; random nonzero lowercase UUIDs, generation 1, null key, unenrolled. Existing: read-only validate → resolver(saved pin) agreement → close validator → preflight recheck → writable SQLiteDatabase DELETE/EXTRA/fullfsync checks → validate again → backup exclusion set/readback → publish. Fresh resolver(nil) loads the isolated existing key or creates once only after owner-established freshness, before writable creation. Existing resolver is load-only. Validate canonical 91-byte P256 SPKI and exact host fingerprint. BUSY fails immediately; no read-only use of writable initializer. Backup exclusion touches only supported private leaf, never unsupported state.
- [ ] GREEN: same command; valid clean reopen preserves IDs/epoch/generation and creates no legacy tables; all refusal fixtures remain unchanged.

### Task 3: Async owner factory and retained failures

**Files:** Extend Core `StatusOnlyTypes.swift` with handles; create `StatusOnlyHost.swift`, `StatusOnlyOwner.swift`; tests `Tests/RemoteExecutionCoreTests/StatusOwnerTests.swift`, `Tests/RemoteExecutionCorePublicAPITests/StatusBoundaryAPITests.swift`.

**Interfaces:** `StatusOnlyHost.open(configuration:) async throws -> StatusOnlyHostHandles`; handles expose `host: TrustedStatusHostHandle`, `controller: StatusControllerHandle`. Host methods `localStatus() async throws -> StatusOnlyLocalSnapshot`, `close() async`; controller `status(over: StatusControllerLease) async throws -> StatusOnlySnapshot`. Remaining host methods follow Tasks 4–5.

- [ ] Write `testInitializationReadCloseShareQueue`: queue-specific sentinel proves all storage/resolver/close work confined off caller/UI; a blocked job preserves FIFO. `testFailedOpenClosesAndAllowsExplicitRetry`: a resolver failure before publication closes partial SQLite/lock resources on the owner queue; a later explicit open with the correct injected identity succeeds and retains the same stable lock inode. `testFailureRetainsLockAndOriginalError`: after handles are published, any storage failure clears memory authority and all later operations return retained failure until explicit close. Public API tests prove controller has only status and no public lease constructor.
- [ ] RED: `T --filter 'StatusOwnerTests|StatusBoundaryAPITests'`; expect missing handles/factory.
- [ ] Implement a dedicated serial DispatchQueue and whole synchronous job submissions using continuations; no suspension between validation/commit. Before publishing handles, failed initialization closes partial resources on that queue and throws. After publication, owner retains journal/lock on failure, invokes configuration.onUnavailable for cancellation-only bridge fencing, and closes only explicitly. Never keep an unreachable failed-initialization owner or auto-retry it. Preserve SQLite terminal diagnostics; ordinary Core policy refusals are not storage failures.
- [ ] GREEN: same command; health precedes stale-lease errors; close invalidates incarnation; legacy actor remains unchanged.

### Task 4: Enrollment contexts and immutable candidate

**Files:** Extend Core owner/types; test `Tests/RemoteExecutionCoreTests/StatusEnrollmentTests.swift`.

**Interfaces:** Host `openEnrollment() async throws -> StatusEnrollmentWindow`; `beginHandshake(_ input: StatusHandshakeInput) async throws -> StatusHandshakeContext`; `recordProofFailure(contextID: UUID) async throws`; `acceptCandidate(contextID: UUID, claimDigest: Data) async throws -> StatusAcceptedCandidate`; `confirmCandidate(candidateID: UUID) async throws`; `rejectCandidate(candidateID: UUID) async throws`; `disconnect(connectionID: UUID) async`.

- [ ] Write `testOneClaimPostFixationNonce`: injected random log proves SAS nonce allocated after exact context/claim fixation; second claim cannot replace key/digest/nonce. `testWrongHostAndSingleUseContext`: both modes refuse wrong host ID/pin before Challenge without consuming invitation/replacing valid lease; same key/different host ID also fails; acceptance/authentication/proof failure consumes context exactly once. `testWindowFailureAndDeadlineLimits`: 120 seconds, equality expired, fifth failed proof closes window, checked overflow refused. `testDelayedProofAndConfirmDisconnectOrder`: ten seconds from trusted acceptance, expired queued acceptance fails; disconnect-first prevents commit, commit-first survives lost delivery.
- [ ] RED: `T --filter StatusEnrollmentTests`; expect missing transitions.
- [ ] Implement fixed contexts using configuration clock; beginHandshake compares host ID/pin to committed identity in both modes before challenge, then validates lengths/mode/placeholders. Verified proof arrives from bridge only; same owner job rechecks context/window/health before consuming context/invitation and fixing candidate, then draws SAS nonce. Authentication/proof failure also consumes context. Proof deadline is ten seconds; accepted candidate retains original 120-second confirmation expiry and live connection. Confirm commits context key only, preserves slot/generation, then invalidates enrollment state. Reject/disconnect/expiry never reopens consumed invitation; restart clears all memory state.
- [ ] GREEN: same command; confirmation accepts no arbitrary key; enrollment status/authentication and revoked re-enrollment refuse.

### Task 5: Normal leases, committed status and local revocation

**Files:** Extend Core owner/journal; tests `Tests/RemoteExecutionCoreTests/{StatusLeaseTests,StatusRevocationTests}.swift`.

**Interfaces:** Host `authenticate(contextID: UUID) async throws -> StatusControllerLease`, `revokeController() async throws`; add local refusal `StatusHostError.notEnrolled` to Core status types. Consumes Task 4's proof-verified fixed context; controller status uses Task 3 signature.

- [ ] Write `testVerifiedReconnectRechecksAndReplaces`: stale/deadline/foreign context leaves valid lease intact; successful replacement invalidates old token, owner/epoch/generation mismatch fails. `testStatusReadsCommittedPolicyOnly`: no writes; capability `.unsupported`. `testUnenrolledRevokeCancelsPendingWithoutWrite`: healthy unenrolled slot closes window/candidate/contexts, throws notEnrolled, and preserves key-null/state/generation/epoch/bytes; stale local confirmation then refuses. `testRevocationCommitAndFaults`: first revoke retains key/increments once, repeat idempotent, Int64 overflow refuses; injected rollback/unknown COMMIT never returns success, all subsequent reads fail and lock remains owned.
- [ ] RED: `T --filter 'StatusLeaseTests|StatusRevocationTests'`; expect missing authentication/revoke logic.
- [ ] Implement same-job health/context/key/current-policy recheck before mint/replace. Revocation checks retained health first and invalidates contexts/candidate/leases before any transition. An unenrolled slot throws notEnrolled with no write; an enrolled slot commits revocation; a revoked slot is idempotent. This ordinary refusal does not quarantine the owner; the bridge's early fence remains disabled until explicit enable. Never reopen a revoked slot. Read committed policy after health and capability validation; no cached fallback. Mark any storage failure terminal even when the shared SQLite kernel could otherwise recover after rollback.
- [ ] GREEN: same command; old leases and late queued reads cannot revive authority; generation bounds match signed Int64 storage.

### Task 6: Fixed frames, messages and invitation codec

**Files:** Add Wire target/product/tests in `Package.swift`; create Wire `Frames.swift`, `Messages.swift`, `Invitation.swift`; test `Tests/RemotePrototypeWireTests/WireEncodingTests.swift`.

**Interfaces:** Define the shared Wire value `StatusEndpoint(ipv4: String, port: UInt16) throws` here (literal `100.64.0.0/10`, port `1024...65535`); later transport performs address-presence checks. `FrameDecodeStep` fields `bytesConsumed: Int`, `frame: WireFrame?`; `FrameDecoder.consume(_ bytes: Data) throws -> FrameDecodeStep` consumes through at most one complete frame and retains at most one bounded partial frame; `WireFrame.encode() throws -> Data`; immutable typed `Hello/Challenge/Proof/CandidateAccepted/EnrollmentCommitted/Authenticated/StatusResponse/Refused`; `Invitation.decode(_ text: String) throws -> Invitation`, `.encode() throws -> String`.

- [ ] Write `testExactGoldenFrames`: assert type/payload bytes `01:162,02:56,03:96,04:64,05:56,06:24,10:0,11:17,7f:1`; status payload is 16-byte epoch then `00`. `testSplitAndCoalescedAuthenticationFrames`: every byte split and one TCP chunk containing CandidateAccepted then EnrollmentCommitted yields both frames in order, one consume result at a time with exact bytesConsumed. `testBoundedAndCanonical`: zero/4097 length before allocation, trailing payload/unknown type, zero placeholders, nonzero normal generation ≤Int64.max, unsupported capability byte refused. `testInvitation103Bytes`: exact canonical `omstatus1:` unpadded base64url; invalid alphabet/padding/whitespace/IPv4/port refused.
- [ ] RED: `T --filter WireEncodingTests`; expect missing Wire target/types.
- [ ] Implement uint32be length including type, limits `1...4096`, fixed-field DTO validation, UUID display-order bytes and design's 103-byte invitation order. Caller processes each result before consuming remaining input under the updated protocol state; do not blanket-reject coalesced frames or queue a second decoded frame. Client RPC pipelining is rejected by connection state in Task 10. Wire imports no Core/SQLite/process code.
- [ ] GREEN: same command; independent literal vectors round-trip without deriving expected bytes from encoder.

### Task 7: Canonical proof, pin and SAS bytes

**Files:** Wire `AuthTranscript.swift`; Transport `PeerAuthentication.swift`; before writing/running PeerAuthentication tests, register `RemotePrototypeTransport` library product/target depending only on Wire and `RemotePrototypeTransportTests` test target in `Package.swift`; tests `Tests/RemotePrototypeWireTests/AuthTranscriptTests.swift`, `Tests/RemotePrototypeTransportTests/PeerAuthenticationTests.swift`.

**Interfaces:** `AuthTranscript.canonicalBytes() throws -> Data`, `.exporterContext() throws -> Data`, `.controllerProofBytes(exporter: Data) throws -> Data`, `.claimDigest(exporter: Data, signature: Data, secretProof: Data) throws -> Data`; `PeerAuthentication.verify(transcript: AuthTranscript, exporter: Data, proof: Proof, invitationSecret: Data?) throws`, `.makeProof(transcript: AuthTranscript, exporter: Data, key: SecKey, invitationSecret: Data?) throws -> Proof`; `comparisonCode(secret: Data, claimDigest: Data, sasNonce: Data) throws -> String`. AuthTranscript fields are the B fields in design order; signature/secretProof are Proof's two Data fields.

- [ ] Write `testLiteralTranscriptVectors`: literal F/B/exporter-context/signing/HMAC/claim/SAS vectors with eight-digit leading-zero case; canonical SPKI prefix/91 bytes and SHA256 pin. `testProofCannotCrossChannelOrClaim`: changed exporter/host/mode/key/nonces/invitation/challenge fails; raw signature is 64 bytes, hash once, both valid S representations accepted; invalid scalars/points rejected. `testNoSASBeforeOwnAcceptedDigest` pins claim acceptance separately from proof validity.
- [ ] RED: `T --filter 'AuthTranscriptTests|PeerAuthenticationTests'`; expect missing transcript/verifier.
- [ ] Implement exact labels, field ordering and length prefixes from spec, P256 X9.63→SPKI reconstruction after curve validation, ECDSA raw representation and crypto HMAC verification. Normal proof requires zero secretProof; exporter must be 32 bytes. SAS uses post-fixation nonce, first eight HMAC bytes as uint64be modulo `100000000`, padded to eight digits. No JSON/DER signatures/platform UUID serialization.
- [ ] GREEN: same command; independent vectors match and every mutation fails.

### Task 8: Isolated key/pin adapters and in-memory certificate

**Files:** Transport `PrototypeKeyStore.swift`, Certificates `HostCertificate.swift`; `Package.swift`/resolved graph; tests `Tests/RemotePrototypeTransportTests/PrototypeKeyStoreTests.swift`, `Tests/RemotePrototypeCertificatesTests/HostCertificateTests.swift`.

**Interfaces:** `PrototypeIdentityRole` cases `.host/.controller`; `PrototypeKeyStore.loadIdentity(role: PrototypeIdentityRole) throws -> SecKey?`, `.createIdentityIfAbsent(role: PrototypeIdentityRole) throws -> SecKey`, `@MainActor loadPairedHost() throws -> PairedHostRecord?`, `@MainActor savePairedHost(_ record: PairedHostRecord) throws`, `@MainActor forgetPairedHost() throws`; record fields `hostID: UUID`, `hostPin: Data`, `endpoint: StatusEndpoint`. Mac `HostCertificate.makeIdentity(key: SecKey, now: Date) throws -> SecIdentity`.

- [ ] Write `testMissingExistingIdentityNeverRotates`, `testQueriesUseOnlyPrototypeServices`: injected Keychain client inspects exact creation accessibility/non-sync attributes, Mac data-protection selection on add/read/update/delete and error propagation with no fallback; tentative pin never overwrites saved pin. `testForgetDeletesOnlyPairedHost`: exact generic-password/service/account/default-private-group query; not-found succeeds, other errors propagate, identity keys and unrelated sentinel items remain unchanged. `testSameKeyCertificateKeepsPin`: in-memory certificate public key equals supplied key; no trust-store or Keychain writes.
- [ ] RED: `T --filter 'PrototypeKeyStoreTests|HostCertificateTests'`; expect missing adapters/target.
- [ ] Implement role-scoped Keychain abstraction and ephemeral test backend. Mac SecItem add/read/update/delete explicitly sets kSecUseDataProtectionKeychain=true; creation uses kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly and kSecAttrSynchronizable=false. Use the signed app's private default access group, no shared group. Pairing pins use generic-password service org.openminis.prototype.controller.hostpins.v1 and exact account paired-host; Forget deletes only that item, keeps identity keys and treats errSecItemNotFound as success. Pin load/save/delete are synchronous MainActor operations so Task 12 can validate its incarnation and persist without an await. Signing/profile failures propagate; never retry using file-based Keychain. Create host key only following fresh-owner resolver call; distinguish not-found from unreadable. Resolve/review exact X509 `1.17.0` graph only after implementation authorization, record versions/licenses/toolchain/OS floors, lock graph; constrain dependency to Mac certificate target. Construct matching SecIdentity in memory. Incompatible floors/API/graph stop this gate for design revision; no silent dependency or identity-policy substitution.
- [ ] GREEN: same command; tests make zero real Keychain writes, dependency graph excludes certificate/Core from iOS runtime links.

### Task 9: Native pinned TLS and exact endpoint

**Files:** Transport `PinnedTLS.swift`, `StatusTLSChannel.swift`; test `Tests/RemotePrototypeTransportTests/PinnedTLSTests.swift`.

**Interfaces:** Consume Task 6's `StatusEndpoint`; `PinnedTLS.clientOptions(pin: Data) throws -> NWProtocolTLS.Options`, `.serverOptions(identity: SecIdentity) throws -> NWProtocolTLS.Options`; `StatusTLSChannel.exporter(context: Data) throws -> Data`; channel exposes immutable `connectionID: UUID`, `acceptedAtNanoseconds: UInt64` and async bounded receive/send plus cancellation.

- [ ] Write `testLoopbackPinAndContextualExporter`: disposable ephemeral loopback pair agrees on 32-byte exporter for SHA256(B); wrong pin fails before Hello/proof, wrong context differs, exporter absence fails. `testPinPolicyAndEndpoint`: same-key certificate reissue/date/CA/hostname accepted by explicit pin policy, wrong curve/key fails; production configuration rejects wildcard/non-tailnet/nonexistent address and never falls back.
- [ ] RED: `T --filter PinnedTLSTests`; expect missing channel/options.
- [ ] Implement NWListener/NWConnection TLS1.3/ALPN/no early data/resumption, certificate algorithm/curve validation and complete SPKI hash pin before protocol messages. Use contextual native exporter with exact label `EXPORTER-OpenMinis-Prototype-v1`. Test-only loopback endpoint injection is internal and unavailable to shipping endpoint policy. Capture acceptance timestamp before owner scheduling. Selected-address disappearance closes listener/channels; rebind only selected saved address.
- [ ] GREEN: same command; missing native API/interoperability is FAIL, never skipped TLS acceptance. No real endpoint or trust-store operation.

### Task 10: Bounded connection pump

**Files:** Transport `ConnectionPump.swift`; test `Tests/RemotePrototypeTransportTests/ConnectionPumpTests.swift`.

**Interfaces:** `ConnectionPump.accept(_ channel: StatusTLSChannel) throws`, `.run(connectionID: UUID, dispatch: @Sendable (WireFrame, UUID) async throws -> WireFrame?) async throws`, `.send(_ frame: WireFrame, over connectionID: UUID) async throws`, `.close(connectionID: UUID)`, `.closeAll()`; injected clock/timers/channel backend. Close methods are thread-safe cancellation only. One serial read/dispatch loop, no detached task per frame.

- [ ] Write `testTwoPendingIncludesCandidate`: third pending connection rejected; candidate counts until commit/close. `testDeadlinesAndBackpressure`: acceptance+10 seconds proof limit, send+10 seconds slow reader closes, exactly one frame (`N <= 4096`, ≤4100 buffered bytes with prefix) and one response pending; pipelined client request/wrong-state/unknown frame closes. `testCoalescedServerTransitions`: CandidateAccepted then EnrollmentCommitted in one receive is processed serially under successive valid states without a phone message between them. `testDisconnectDiscardsLateResponse`: old channel delivery is dropped.
- [ ] RED: `T --filter ConnectionPumpTests`; expect missing pump.
- [ ] Implement fixed resource/state accounting, incremental header validation before allocation, cancellable continuous-clock timers and serialized dispatch. Consume one FrameDecodeStep, process it/change state, then consume remaining bytes; retain at most one frame. Reject client RPC pipelining at request-state validation. Do not treat completed proof as authenticated enrollment; pending local candidate retains pool slot. Timer expiry cannot renew invitation or accept another SAS attempt. Socket caps are resource bounds, not hostile-tailnet availability guarantees.
- [ ] GREEN: same command; fake slow reader proves bounded memory and deterministic teardown, with no real sleeps/tailnet sockets.

### Task 11: Trusted bridge, strict allowlist and ServiceFence

**Files:** Host target `HostService.swift`, `HostRPCDispatcher.swift`, `ServiceFence.swift`; add Mac-only Host target/product/tests in `Package.swift` depending on Core/Transport/Certificates; test `Tests/RemotePrototypeHostTests/HostBridgeTests.swift`.

**Interfaces:** `HostService.enable(configuration: StatusOnlyHostConfiguration, endpoint: StatusEndpoint) async throws`, `.disable() async`, `.revokeController() async throws`; `HostRPCDispatcher.handle(_ frame: WireFrame, connectionID: UUID) async throws -> WireFrame?`; `ServiceFence.disable()`, `.isDisabled: Bool`. Factory supplies a fresh fence per explicit enable; a disabled fence never resets.

- [ ] Write `testProofVerifiedBeforeOwnerAndRechecked`: no accept/auth call for failed proof; delayed valid proof hits owner deadline check; failed proof leaves old lease/channel intact. `testStatusOnlyAllowlist`: only authenticated type10 routes to controller.status; enrollment status, arbitrary opcodes/legacy mutation/reset/process routes close. `testRevokeFailureAndLateDelivery`: fence/channel close precedes queued write; blocked owner and unknown commit yield no success; late callback/read cannot send or reopen. `testDirectUnenrolledRevokeLeavesFenceDisabled`: error is notEnrolled, no durable-success claim, channels stay closed until explicit enable. `testLostCommitAckUsesNormalAuth`: enrollment commit then disconnect persists exact key; normal reconnect works without replay. `testDiagnosticRedaction`: captured logs/descriptions contain none of the fixture keys, invitation text/secret, exporter, proof/signature/nonces or comparison code.
- [ ] RED: `T --filter HostBridgeTests`; expect missing bridge/fence.
- [ ] Implement transcript retention per opaque context, signature/HMAC verification outside Core, then owner's exact accept/auth call. Send candidate only after fixation, committed only after commit; normal successful lease replacement closes old channel before Authenticated. Dispatch and response delivery both check cancellation-only fence. onUnavailable synchronously disables fence/closes channels and schedules transcript clearing without awaiting owner; no fallback to localStatus/cache. Local revoke latches before awaiting owner. Fence never mints leases or writes policy.
- [ ] GREEN: same command; deterministic queue barriers verify both ordering outcomes; already-dispatched responses are explicitly outside recall guarantee.

### Task 12: Standalone app states and unsigned projects

**Files:** Create `Sources/RemoteHostPrototypeModel/{HostModel,PrototypeInstallationSelection}.swift`, `Sources/RemoteControllerProbeModel/ProbeModel.swift`; register separate products/targets and `Tests/RemoteHostPrototypeModelTests/HostModelTests.swift`, `Tests/RemoteControllerProbeModelTests/ProbeModelTests.swift` in `Package.swift`. Prototype project/shared schemes and App/View files use these model products.

**Interfaces:** `@MainActor HostModel` actions enable/disable/openEnrollment/confirm/reject/revoke; `@MainActor ProbeModel` actions enterInvitation/connect/reconnect/disconnect/editEndpoint plus `forgetPairing() throws`. `PrototypeInstallationSelection.parse(arguments: [String]) throws -> UUID?`; `.resolve(applicationSupport: URL, installationID: UUID?) -> URL`. The local option `--prototype-installation <uuid>` accepts one nonzero canonical lowercase UUID; none selects the default leaf. Probe connection state carries connection UUID; accepted-claim comparison state carries its own claimDigest. Inject HostService/channel/key/pin stores.

| Test | Assertions |
| --- | --- |
| `testLaunchDisabledAndWindowCloseKeepsHosting` | Launch disabled; explicit enable required; closing the window retains enabled hosting; disable/Quit closes it. |
| `testNoCodeForOtherClaimOrDisconnectedCandidate` | Display only the probe's own accepted digest; clear comparison state on disconnect/failure. |
| `testOldConnectionCannotUpdateScreen` | Discard responses from superseded local incarnations. |
| `testForgetFencesDelayedAuthentication` | Invalidate incarnation/cancel channels/clear tentative state before exact pin deletion; delayed success cannot restore pin; preserve identity key and avoid reconnect; deletion errors remain visible/disconnected. |
| `testFreshInstallationSelection` | Exact default/UUID leaf under injected ApplicationSupport; reject missing/duplicate/malformed/zero UUID and traversal; new store has new host ID/epoch while old revoked store and key remain unchanged. |
| `testUnenrolledRevokeControlDisabled` | Disable Revoke unless enrolled. |
| `testLostAckKeepsTentativePinAndSameKey` | Save only after normal authentication; preserve an existing pin, retain host ID/pin on endpoint edit, and never replay enrollment. |

- [ ] Write the named tests in the table. Across states assert “Commands unavailable”; suspension/address loss produces visible disconnect.
- [ ] RED: `T --filter 'HostModelTests|ProbeModelTests'`; expect missing models.
- [ ] Implement ProbeModel's text invitation entry (scanner optional/deferred), comparison/status/reconnect and explicit errors. Only ProbeModel persists pins: recheck incarnation immediately before synchronous save/delete, with no await between check and operation. Forget keeps private identity and changes no Mac policy; it starts no enrollment/reconnect.
- [ ] Implement `PrototypeInstallationSelection` using the interface above and fixed leaf `<ApplicationSupport>/OpenMinisPrototype/installations/<uuid-or-default>`. Pass that directory through existing configuration. No peer field/arbitrary path may select it; never reset/delete an old store. Real state/Keychain operations remain the later manifest request.
- [ ] Implement HostModel's explicit hosting, confirmation/rejection and revocation states. Disable Revoke unless enrolled. Hosting starts disabled each launch; window close retains enabled hosting, disable/Quit closes it.
- [ ] Create the standalone project/shared schemes `RemoteHostPrototype` and `RemoteControllerProbe`. Mac-only RemoteHostPrototypeModel depends on RemotePrototypeHost; RemoteControllerProbeModel depends only on Wire/Transport. App/View files import their model product. Phone links no Core/Host/Certificates. Use exact bundle/service IDs, signing unset, Mac sandbox disabled, and no privacy prompts/cloud/production links. Package model tests exercise the models directly.
- [ ] GREEN: same command, then unsigned build commands below; both compile. This proves app-state fixtures/compilation, not signed launch, native UI use or physical acceptance.

### Task 13: Combined verification, independent review and physical manifest

**Files:** `prototype/QUALIFICATION.md`, `src/remote/README.md`; final read-only whole-branch review includes every changed implementation/project file.

**Interfaces:** Evidence rows use requirement ID, command/test, source/artifact revision, result PASS/FAIL/NOT RUN, and evidence class. No executable qualification script is added.

- [ ] Write qualification matrix/manifest rows with signed/physical results initially NOT RUN. Reuse Task 11's behavioral router tests; add no source-string test or dispatcher-mirroring test for this documentation task.
- [ ] Inspect actual Package.swift target/dependency graph, app imports/project linkage and unsigned linked artifacts: phone contains only RemoteControllerProbeModel/Wire/Transport and frameworks, excluding Core/Host/Certificates. Record artifact paths and concrete inspection evidence; this is source/link evidence, not runtime acceptance.
- [ ] Obtain independent fresh read-only whole-branch review using neutral base/head refs, repository guidance and accepted designs, not implementer findings. Review identity→context→candidate→lease→status and fence→revocation→delivery across all components; resolve confirmed findings with bounded integration corrections before final verification. Primary owns any Git operation.
- [ ] Run full package suite and both unsigned builds once after final changes. Report legacy 69 historical cases preserved plus new-case counts, actual commands/results, skipped gates and limitations. Run `git diff --check` only at later implementation gate. No runtime success claim from source/link checks.

## Commands for later authorized Gate A

Run from repository root, serialize shared outputs. RED/GREEN task commands expand `T` exactly as defined above. Use the full suite after integration:

```sh
xcrun swift test --package-path src/remote --scratch-path /private/tmp/openminis-status-package
xcodebuild -project src/remote/prototype/RemoteExecutionPrototype.xcodeproj -scheme RemoteHostPrototype -destination 'generic/platform=macOS' -derivedDataPath /private/tmp/openminis-status-mac CODE_SIGNING_ALLOWED=NO build
xcodebuild -project src/remote/prototype/RemoteExecutionPrototype.xcodeproj -scheme RemoteControllerProbe -destination 'generic/platform=iOS' -derivedDataPath /private/tmp/openminis-status-ios CODE_SIGNING_ALLOWED=NO build
git diff --check
```

Gate A passes only with current-source fixtures, actual disposable TLS interoperability, unsigned compilation and independent review. Keep original 69 legacy tests; do not narrow the full-suite command or interpret skipped native tests as passing. Factory/owner responsiveness is demonstrated with deterministic blocked-job sentinels; configured fullfsync/readback does not prove physical durability. Crash-journal refusal is intentional and not recovery qualification.

## Requirement → task/test → evidence gate

| ID | Task and named evidence | Gate |
| --- | --- | --- |
| A1 | 8/12/13: model tests, actual target/import/link graph, unsigned artifacts | A automated/source |
| A2 | 9: `testPinPolicyAndEndpoint`; selected-address loss | A fixture; physical later |
| A3 | 7/9/11: transcript mutations, contextual loopback exporter, proof-before-owner | A; physical pin/exporter later |
| A4 | 4/5/12: one claim, disconnect/confirm ordering, revoke persistence and unenrolled refusal/UI | A; physical flow later |
| A5 | 4/7/12: post-fixation random log, SAS vectors, own accepted claim | A; physical racing phones later |
| A6 | 1/2/3/5: shared lock, exact table, queue sentinel, opaque leases | A |
| A7 | 1/2: validated Finder metadata exception, untouched companion/header/schema fixtures, no validator writes | A; no crash-recovery claim |
| A8 | 6/11/13: `testStatusOnlyAllowlist`, constant zero StatusResponse, actual graph/link inspection | A |
| A9 | 3/5/11: retained errors, unknown COMMIT, fence-before-write/late delivery | A; physical revoke later |
| A10 | 2/8/12: resolver agreement, Mac data-protection queries, scoped Forget and stale-save fencing | A injected; real Keychain later |
| A11 | 4/10: expiry/fifth failure/two pending/backpressure | A; external reachability policy later |
| A12 | 12/13: unsigned commands, classified evidence, separate manifest | A; physical NOT RUN |

The later physical manifest must name source/dependency/artifact hashes, final registered bundle IDs, team/OS/hardware, selected tailnet address/port and phone-only external reachability policy. Verify identifier availability before registration; reverse-DNS spelling requires no domain ownership. Signing stays unset for Gate A.

For the signed Mac artifact, record its private default access group, actual `com.apple.application-identifier`, signing identity/route and matching embedded provisioning profile. Local qualification may use Apple Development plus a development profile; Developer ID distribution requires its corresponding profile. Record the iOS `application-identifier` and profile too. Inspect actual signatures/entitlements and embedded profile authorization; never infer them from project settings or fake-Keychain tests. No custom shared Keychain group is required.

Record applicable macOS firewall policy and the possible incoming-connection alert, with its authorized response. Eligible signed software may be allowed automatically, so the alert is conditional. A blocked connection is a visible failed/blocked case; never disable the firewall or change global policy automatically.

The manifest lists each unused Mac installation UUID and resolved directory, the existing isolated identity to retain, and the exact phone paired-host item that Forget will delete. For a repeated consumed/revoked case: explicitly disable/Quit/close the old host owner; preserve its directory and lock; invoke local phone Forget; start the Mac using a new unused --prototype-installation UUID; verify new host ID/epoch and unchanged private keys; then use the new invitation and local code confirmation. Keep the old revocation intact. Forget alone changes no Mac policy. Do not depend on app reinstall, erase a whole Keychain, reset a database or silently choose fresh state after refusal.

Finite physical cases are cellular pinned TLS/exporter; wrong-key/same-key reissue; enrollment race/expiry/replay/lost ACK; reconnect then revoke/refused reconnect; scoped Forget and explicit fresh-installation enrollment; address loss; actual Keychain lock/restart; and redacted-log inspection. Signing, installation, real scoped Keychain deletion, firewall responses, Tailscale-policy changes and experiments all require that separate bounded request; none occurs during this documentation revision.

No command/helper/process/crash-recovery evidence belongs to this manifest. Parent execution gates B1–B7 remain separate; issues #2–#4 receive bounded status work only, #5/#6 remain open. Completion of this documentation means the design and plan are ready for review; implementation, automated results, commits and physical qualification remain unperformed.
