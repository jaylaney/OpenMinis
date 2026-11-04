# Authenticated-status prototype

Date: 2026-11-02
Revision: 3 — 2026-11-04 approved PR #7 lifecycle and confirmation corrections.
Status: Gate A implementation is on PR #7. The user authorized the four confirmed review fixes on 2026-11-04; signed/physical and execution gates remain separate.
Baseline: fork `main` at `fcb9bb8f57cfd7241c01e22bdd87769f91364e7d` (merged admission foundation).
Parent: [remote execution design, revision 12](2026-10-30-remote-execution-design.md).

## Outcome and selected approach

A foreground iPhone probe can enroll with an awake Mac, authenticate over externally installed Tailscale, read committed status, disconnect and authenticate again. The Mac can revoke that phone locally. Every screen states that commands are unavailable. This increment contains no execution route, helper, script, approval, process scan, output stream, model or production agent integration.

The user selected a smaller status-only increment after review of the broader scripted prototype. The protected-copy recovery design and its 128 MiB startup limit are removed from this increment.

| Approach | Tradeoff | Decision |
| --- | --- | --- |
| Status plus commands, migrations and recovery-copy machinery | Exercises more of the product, but couples transport qualification to several undecided kernels. | Deferred. |
| Status with fresh stores and validated clean rollback-store reopen | Establishes enrollment and the controller boundary while refusing recovery states untouched. A crash can leave the prototype unavailable. | Selected. |
| Fresh state on every launch | Simplest opening path, but cannot establish persistent enrollment/revocation or normal reconnect across launches. | Rejected. |

Implementation defaults below are author choices implementing that selection. They are frozen for the proposed plan, not claims of tested native behavior. The original review remains historical evidence; this document supersedes the earlier scripted-prototype proposal at this path.

## Approved PR #7 corrections

The 2026-11-04 correction request covers four behavior issues:

- An explicit local-policy load can open an existing committed status installation without activating networking or invoking TLS credential/certificate/listener setup. It uses the same serial Core owner, lock, validation and required identity checks. It refuses fresh/missing/zero-byte stores without creating a policy, epoch, identity, state leaf or main file. Explicit Enable retains the original fresh-store behavior. Loading is a user action, never launch/onChange/poll behavior; it does not automatically reopen a retained failed owner.
- Owner lifetime is independent from hosting readiness. A retained owner, including after revocation or failure, remains explicitly closeable. Revocation is available for an enrolled locally loaded slot even while hosting is disabled. Close/disable/Quit cancel first and close the owner; failure does not silently release/reopen it.
- Trusted confirmation returns its committed snapshot only after successful COMMIT. The bridge reports a committed result independently of whether its EnrollmentCommitted send completed. A late disconnect/send failure cannot relabel a committed enrollment as failed. Genuine storage/unknown-commit failures still propagate and fence; a subsequent readiness failure stays visible alongside an already-known committed outcome. No retry/replay is introduced.
- Open enrollment is disabled for every non-closed owner enrollment phase, including a fixed candidate awaiting CandidateAccepted send completion. Core remains the authority; candidate publication still occurs only after send completion. Polling reads the owner phase without creating another expiry clock.

The [focused fix plan](../plans/2026-11-04-remote-status-pr7-fixes.md) implements these corrections. The other PR comments are deferred or disputed as assessed; no wire, routing, recovery or optional cleanup redesign is included.

## Requirements and boundaries

| ID | Contract |
| --- | --- |
| A1 | Separate Mac/iPhone targets; production `src/ios`, project, credentials, sync, providers and user data remain outside this work. |
| A2 | Manual literal Tailscale IPv4 and port; exact-address binding only. No wildcard, LAN/public fallback, relay, discovery or embedded VPN. |
| A3 | TLS 1.3, pinned P256 SPKI, exporter-bound controller proof; a network address and a claimed UUID confer no authority. |
| A4 | One never-enrolled/enrolled/revoked controller slot; one immutable candidate per invitation; local Mac confirmation only. |
| A5 | The comparison code uses fresh host randomness disclosed only after the candidate is fixed. A phone displays a code only for its own accepted claim. |
| A6 | One store/lock/serial owner for prototype SQLite, policy, pending enrollment and leases; no second allowlist or raw-handle escape. |
| A7 | Unsupported state is refused before mutation. Only clean rollback stores are supported; all recovery companions are refused untouched. |
| A8 | Only authenticated status is a controller RPC. No legacy coordinator forwarding, execution, reset, replacement, session or process RPC. |
| A9 | Local revocation fences connections before its write; durable success requires commit. Storage failure disables service without cached-status fallback. |
| A10 | Keys and phone pins use isolated non-synchronizable Keychain services. Missing or mismatched keys never cause silent replacement. |
| A11 | Two pending sockets and deadlines bound resources, not hostile-tailnet availability. Initial qualification restricts reachability to the participating phone. |
| A12 | Automated/unsigned evidence and signed physical evidence are reported separately. No implementation or live action is authorized by this document. |

## Components and ownership

| Target | Responsibility |
| --- | --- |
| Existing `RemoteExecutionCore` | Reuse file ownership and SQLite transaction kernel; add a status-only schema/factory, serial executor and narrow handles. |
| `RemotePrototypeWire` | Fixed binary frames, invitation codec, canonical crypto bytes and immutable message types. No Core, SQLite or process dependency. |
| `RemotePrototypeTransport` | Network/Security/CryptoKit adapters, pinned TLS, proof verification, Keychain adapters and bounded connection pump; depends on Wire only. |
| `RemotePrototypeCertificates` | Mac-only self-signed certificate construction with exact candidate X509 1.17.0; no trust-store installation. |
| `RemotePrototypeHost` | Mac-only bridge between transport and trusted Core handles. Implements the status allowlist. |
| Standalone project/state | `RemoteHostPrototype` and `RemoteControllerProbe`; no helper target. Testable `RemoteHostPrototypeModel` depends on Host; `RemoteControllerProbeModel` depends only on Wire/Transport. iOS links only its controller model, Wire and Transport. |

Use `src/remote/prototype/RemoteExecutionPrototype.xcodeproj`. Unsigned prototype bundle IDs are `org.openminis.prototype.host` and `org.openminis.prototype.controller`. Their reverse-DNS spelling does not assert domain ownership. Before registration/signing, verify availability under the selected team and record final IDs in the approved physical manifest. Keychain services are `org.openminis.prototype.host.identity.v1`, `org.openminis.prototype.controller.identity.v1` and `org.openminis.prototype.controller.hostpins.v1`. Leave signing teams/certificates unset. Use separate application state and disposable test directories. Mac App Sandbox is disabled; do not request privacy grants automatically.

The status factory uses the existing names `admission.lock` and `admission.sqlite3` in its own private installation directory. It does not instantiate `AdmissionJournal` or `AdmissionCoordinator`, create legacy execution tables or open a parallel database. Status and legacy open profiles are mutually exclusive under the same stable lock. The legacy opener gains a pre-writable-open refusal for the reserved status application ID, preventing it from creating execution tables in a status store after that owner closes. Existing legacy behavior otherwise remains unchanged.

All prototype initialization, close, policy, enrollment and lease work runs on one dedicated serial Dispatch queue. The host bridge additionally has a cancellation-only thread-safe `ServiceFence`: it can disable transport, never mint authority or persist policy. An async facade submits whole synchronous jobs: no `await` occurs between policy validation and commit. Retain the legacy actor and explicitly blocking synchronous initializer for compatibility; prototype UI never calls it. Moving the entire legacy actor onto this queue is deferred. Fail fast on SQLite BUSY; no new busy wait policy is introduced.

## Frozen status store

Application ID is `1330467668` (`0x4f4d5354`, OMST); `user_version` is `1`. There is exactly one application table, with this DDL. Compare its stored SQL and implicit index definitions against the same DDL instantiated in an in-memory reference database; do not write a SQL normalizer.

```sql
CREATE TABLE prototype_status (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1),
    host_id TEXT NOT NULL UNIQUE CHECK(typeof(host_id) = 'text' AND length(host_id) = 36),
    storage_epoch TEXT NOT NULL UNIQUE CHECK(typeof(storage_epoch) = 'text' AND length(storage_epoch) = 36),
    host_spki_sha256 TEXT NOT NULL CHECK(typeof(host_spki_sha256) = 'text' AND length(host_spki_sha256) = 64 AND host_spki_sha256 NOT GLOB '*[^0-9a-f]*'),
    controller_id TEXT NOT NULL UNIQUE CHECK(typeof(controller_id) = 'text' AND length(controller_id) = 36),
    controller_generation INTEGER NOT NULL CHECK(typeof(controller_generation) = 'integer' AND controller_generation >= 1),
    controller_state TEXT NOT NULL CHECK(controller_state IN ('unenrolled', 'enrolled', 'revoked')),
    controller_spki_der_hex TEXT CHECK(controller_spki_der_hex IS NULL OR (typeof(controller_spki_der_hex) = 'text' AND length(controller_spki_der_hex) = 182 AND controller_spki_der_hex NOT GLOB '*[^0-9a-f]*')),
    CHECK((controller_state = 'unenrolled' AND controller_spki_der_hex IS NULL) OR (controller_state IN ('enrolled', 'revoked') AND controller_spki_der_hex IS NOT NULL))
)
```

Application validation additionally requires one row, nonzero canonical lowercase UUIDs, a canonical valid P256 SPKI when present, exact host fingerprint equality, and no extra tables, views, triggers or user indexes. Expected implicit unique indexes cover host ID, epoch and controller ID, in DDL order. Run `PRAGMA integrity_check` and require only `ok`. A fresh transaction sets application ID/version, creates the table and initial row together: random host/epoch/controller-slot UUIDs, supplied host-key fingerprint, generation 1, `unenrolled`, null controller key.

| Operation | Persistent change |
| --- | --- |
| Local confirmation | `unenrolled → enrolled`, exact accepted key; retain slot ID/generation. |
| Local revocation | `enrolled → revoked`, retain key, increment generation once. Repeated revocation is idempotent; overflow refuses. |
| Revocation while unenrolled | Cancel pending enrollment in memory, then throw `StatusHostError.notEnrolled`; no database write or generation change. The bridge remains disabled by its early fence. |
| Authentication/status | No persistent change; leases are incarnation-bound memory only. |
| Re-enrollment/replacement/reset/migration | Unavailable. Revocation never reopens the slot. |

There are no run, request, approval, event, process or output tables. Consequently this increment has no append-only output growth or retained-output budget. A future execution schema requires a separate plan; no v1-to-v2 migration is specified here.

### Clean opening, in order

1. Prepare the private leaf using existing ownership/privacy rules; acquire and retain the stable lock. Reinspect under ownership. Never unlink or replace the lock.
2. Permit the lock and main database, plus the exact Finder metadata name `.DS_Store` only when `lstat` shows a regular, effective-user-owned, single-link file. Ignore its contents without opening, changing or deleting it. Refuse symlink/nonregular/foreign-owned/multiply-linked metadata and every other entry, including empty `-journal`, `-wal`, `-shm`, super-journals and unknown companions, before SQLite touches the original. Never traverse referenced journal paths. Reinspection repeats the metadata checks; its allowed appearance/disappearance/content changes do not change the authoritative file inventory.
3. A missing or zero-byte main file with no forbidden entries is fresh. Otherwise read its header using no-follow file access: require a valid SQLite header, rollback read/write format bytes `1/1`, OMST application ID and version 1. Refuse malformed, unversioned, foreign or WAL-format input. Keep existing regular-file/euid/link/mode checks; do not repair existing permissions.
4. Open the existing clean file explicitly read-only with no CREATE, writable pragmas, ATTACH or recovery bypass. Validate the exact schema, data and integrity. Do not use the current writable `SQLiteDatabase` initializer as this probe.
5. Resolve the saved Keychain key against the read-only validated fingerprint before a writable open. Fresh state supplies no required pin: load an existing isolated key or create it once. Existing state supplies its required pin: missing/unreadable/mismatched identity is unavailable, never permission to create or rotate a key.
6. Close the validator and verify unchanged file identity, size, content and companion inventory under the retained lock. Only then open writable, configure/read back the existing DELETE/EXTRA/fullfsync policy and validate again before exposing handles. Apply/read back backup exclusion on the supported private leaf before publishing readiness; an exclusion error disables hosting. Publish handles only after identity/store agreement.

Unsupported database/companion bytes, modes, inodes, epoch and bindings remain unchanged. Creation of a previously absent ownership lock is permitted infrastructure. No copy preflight, `immutable=1`, recovery, migration, journal cleanup, reset or automatic new installation is permitted.

**Deliberate limitation:** a crash during a transaction can leave a rollback journal, making this prototype refuse reopen. Keep that state for diagnosis. General same-store crash recovery is a later design gate before commands, not an acceptance claim of this status increment. Fresh storage never proves prior command processes absent; the future execution design must reconcile them independently.

## Core interfaces

Names below are the integration contract; additional private helpers are builder choices. All methods are async queue submissions except value construction. Keys are canonical 91-byte SPKI DER `Data`; pins/digests/nonces are 32-byte `Data`, checked before use.

```swift
StatusOnlyHost.open(configuration: StatusOnlyHostConfiguration) async throws -> StatusOnlyHostHandles
// configuration: directory URL; injected monotonic clock/random source;
// onUnavailable: @Sendable () -> Void (disable/close only, never reenter Core);
// identity resolver(requiredPin: Data?) throws -> Data (resolved public SPKI).
// allowsFreshStore: Bool = true; false refuses fresh input before identity/DB creation.
// nil is supplied only for owner-established fresh state; existing identity must match.

StatusOnlyHostHandles.host: TrustedStatusHostHandle
StatusOnlyHostHandles.controller: StatusControllerHandle

TrustedStatusHostHandle.localStatus() async throws -> StatusOnlyLocalSnapshot
TrustedStatusHostHandle.openEnrollment() async throws -> StatusEnrollmentWindow
TrustedStatusHostHandle.beginHandshake(_ input: StatusHandshakeInput) async throws -> StatusHandshakeContext
TrustedStatusHostHandle.recordProofFailure(contextID: UUID) async throws
TrustedStatusHostHandle.acceptCandidate(contextID: UUID, claimDigest: Data) async throws -> StatusAcceptedCandidate
TrustedStatusHostHandle.confirmCandidate(candidateID: UUID) async throws -> StatusOnlySnapshot
TrustedStatusHostHandle.rejectCandidate(candidateID: UUID) async throws
TrustedStatusHostHandle.authenticate(contextID: UUID) async throws -> StatusControllerLease
TrustedStatusHostHandle.disconnect(connectionID: UUID) async
TrustedStatusHostHandle.revokeController() async throws
TrustedStatusHostHandle.close() async
StatusControllerHandle.status(over: StatusControllerLease) async throws -> StatusOnlySnapshot
```

`StatusHandshakeInput` contains connection UUID, trusted connection-acceptance time, mode, host ID/pin, canonical controller SPKI, client nonce and invitation ID. Injected clock values are continuous monotonic nanoseconds; checked deadline addition refuses overflow. The authentication deadline is acceptance time plus ten seconds, not ten seconds after a delayed owner job begins. `beginHandshake` first requires Hello host ID and pin to equal the committed local host identity in both modes. A mismatch refuses without replacing a valid lease or consuming an invitation. It then fixes those fields and returns an opaque context UUID, server nonce, assigned controller ID/generation, plus invitation secret only to the trusted host bridge for enrollment proof verification. Enrollment challenge ID/generation are zero; normal values come from committed policy. Contexts expire with their connection's ten-second authentication deadline and are consumed on candidate acceptance, normal authentication or proof failure; they cannot be reused.

`StatusEnrollmentWindow` contains host ID/pin, random invitation ID/secret and monotonic deadline. `StatusAcceptedCandidate` contains candidate UUID, connection UUID, claim digest and post-acceptance SAS nonce. Its key is the context's fixed key; confirmation accepts no arbitrary replacement key. The host bridge retains the crypto transcript per context, verifies proof before calling `acceptCandidate`/`authenticate`, and computes display bytes using Wire. It cannot extend invitation/context lifetime. Only the owner owns mutable candidate validity, policy and leases.

`StatusControllerLease` has no public initializer, wire representation or Codable conformance. It captures owner incarnation, connection token/ID, epoch and controller generation. Mint/replace only after proof and same-job policy recheck. Bad/foreign/stale proofs leave an existing valid lease intact. Every status checks retained health first, then current lease/generation/epoch, before reading committed state. `StatusOnlySnapshot` contains host ID, epoch, assigned controller ID/generation and execution capability `.unsupported`; the local snapshot additionally contains enrollment/policy/readiness for Mac UI. Neither exposes sessions or legacy admission APIs.

The Mac Revoke control is disabled unless the slot is enrolled. A direct trusted revocation call on an unenrolled slot still clears its pending window/candidate/contexts and returns `StatusHostError.notEnrolled` after the normal health check, without quarantining the healthy owner or changing the store. Because the bridge fences first, that attempted operation leaves transport disabled until a later explicit enable; it never reports durable revocation.

On local revocation, the bridge first latches `ServiceFence` and closes channels without waiting for the owner queue. The queued owner job then invalidates leases/candidates and performs the policy write; report durable success only after commit. Dispatch and response delivery check the fence, so a late job cannot reopen transport. A response already dispatched before revocation cannot be recalled.

If opening fails before handles are published, close partial SQLite/lock resources on the owner queue and throw; there is no unreachable retained owner. A later explicit enable may attempt opening again under the same compatibility rules.

After handles are published, any storage failure synchronously invokes the non-reentrant `onUnavailable` cancellation callback, clears candidate/leases and retains the failed owner/lock until explicit close. The callback disables `ServiceFence` and closes channels; it receives no raw error or secret material. The owner retains the original terminal error.

Unknown commit returns no success/capability. No automatic reopen/retry. A late queued read cannot revive service.

## Wire v1

Frame: `uint32be N || uint8 type || payload`; `N` includes type and must be `1...4096` before allocation. Exact payload lengths are mandatory. Unknown type, wrong state, trailing bytes, invalid point or missing exporter closes the connection. One outstanding request, no client RPC pipelining. TCP may split or coalesce frames, including CandidateAccepted followed by EnrollmentCommitted; consume one bounded frame at a time and evaluate the next against the resulting protocol state. All integers are unsigned big-endian. UUIDs are 16 bytes in hexadecimal display order, with zero allowed only for designated placeholders.

Wire public keys are validated P256 X9.63 points, 65 bytes `04 || X || Y`. Canonical SPKI is hex prefix `3059301306072a8648ce3d020106082a8648ce3d030107034200` followed by the point, totaling 91 bytes. Pin is SHA256 of those 91 bytes. Certificate validation checks key algorithm/curve before reconstruction.

| Type | Direction | Exact payload (bytes) |
| --- | --- | --- |
| `01 Hello` | Phone → Mac | mode(1), hostID(16), hostPin(32), controllerPoint(65), clientNonce(32), invitationID(16): 162 |
| `02 Challenge` | Mac → phone | serverNonce(32), controllerID(16), generation(8): 56 |
| `03 Proof` | Phone → Mac | raw P256 signature(64), secretProof(32): 96 |
| `04 CandidateAccepted` | Mac → phone, enrollment | claimDigest(32), sasNonce(32): 64 |
| `05 EnrollmentCommitted` | Mac → phone, after commit | claimDigest(32), controllerID(16), generation(8): 56 |
| `06 Authenticated` | Mac → phone, normal | controllerID(16), generation(8): 24 |
| `10 StatusRequest` | Authenticated phone → Mac | empty |
| `11 StatusResponse` | Mac → authenticated phone | storageEpoch(16), executionSupported(1, must be zero): 17 |
| `7f Refused` | Mac → phone, terminal | reason(1): generic=1, unavailable=2, staleChannel=3 |

Type numbers are hexadecimal. Modes: enrollment=1, normal=2. Normal Hello invitation ID is zero. Enrollment Challenge controller ID and generation are zero. Normal generation must fit signed Int64 and match committed policy. `executionSupported=0` is a protocol constant, not a mutable readiness flag. Other values are protocol errors. Status failure closes the connection; no cached response or unsolicited snapshot is allowed.

### Canonical cryptographic bytes

`F(label, fields...)` is `uint16be ASCII-label-length || ASCII-label`, then for each field `uint32be byte-length || bytes`. No terminators, JSON, text UUIDs or implicit platform serialization.

```text
B = F("OpenMinis/Prototype/v1/handshake",
      mode, hostID, hostPin, canonicalControllerSPKI,
      clientNonce, serverNonce, invitationID, challengeControllerID, challengeGeneration)
E = TLS exporter(label="EXPORTER-OpenMinis-Prototype-v1", context=SHA256(B), length=32)
signature = ECDSA-P256-SHA256(F("OpenMinis/Prototype/v1/controller-proof", B, E))
secretProof = HMAC-SHA256(invitationSecret,
      F("OpenMinis/Prototype/v1/invitation-proof", B, E, signature))
claimDigest = SHA256(F("OpenMinis/Prototype/v1/claim", B, E, signature, secretProof))
sasBytes = HMAC-SHA256(invitationSecret,
      F("OpenMinis/Prototype/v1/comparison", claimDigest, sasNonce))
code = uint64be(sasBytes[0..<8]) mod 100000000
```

Normal Proof has all-zero secretProof and uses no invitation secret. Raw signature is `r[32] || s[32]`, not DER; validate scalar ranges/ECDSA and hash signing bytes exactly once. Accept either valid S representation. Compare HMACs using the crypto API. Code renders exactly eight zero-padded decimal digits.

### Enrollment and authentication transitions

| State | Event and result |
| --- | --- |
| Closed, never enrolled | Local Mac opens 120-second window; random invitation ID/256-bit secret. |
| Open | Pinned TLS Hello/Challenge/valid Proof; owner atomically consumes invitation and fixes exact claim. |
| Candidate fixed | Only now generate fresh 32-byte SAS nonce; send CandidateAccepted and display code on Mac. |
| Candidate fixed | Phone displays only if accepted digest equals its own exact transmitted claim on this pinned connection. |
| Candidate fixed | Local confirm checks same candidate/live connection, health and original expiry, then commits exact key. |
| Committed | Send EnrollmentCommitted after successful commit; close enrollment transport. |
| Rejected/expired/disconnected before commit | Invalidate candidate/window; consumed invitation stays consumed. |
| Normal reconnect | New TLS Hello/Challenge/Proof; owner rechecks committed host identity and active key/generation, replaces lease, closes old channel, then emits Authenticated. |
| Authenticated | StatusRequest revalidates lease in owner job and returns committed epoch/unsupported constant. |

The SAS nonce must be generated after claim fixation; earlier server nonce/exporter values cannot substitute. No key/nonce/proof revision, challenge retry or second SAS attempt is permitted on that claim. `now >= deadline` is expired. Restart invalidates all invitations/candidates/contexts/leases. Owner jobs recheck deadlines when dispatched, not only when frames arrive.

Only the trusted local Mac action confirms. A phone frame never confirms enrollment. Status is forbidden during enrollment. Confirm/disconnect is serialized: disconnect first prevents commit; commit first persists enrollment despite lost delivery. A lost success ACK is resolved by a new normal authentication using the existing phone key and tentative invitation pin, never enrollment replay. Persist the phone's paired-host record only after successful normal authentication; a tentative pin cannot overwrite an existing saved pin. Disconnected/failed candidates clear the phone's code immediately. Saved endpoint edits retain host ID/pin.

### Portable invitation and native TLS

Text and QR contain exactly `omstatus1:<unpadded-base64url(binary)>`. Binary is 103 bytes: version `01`(1), IPv4(4), port(2), host UUID(16), SPKI pin(32), invitation UUID(16), secret(32). Require exact prefix/alphabet/length and canonical re-encoding; no whitespace, padding or extra fields. IPv4 must be in `100.64.0.0/10`; port is `1024...65535`, default 49152. The host enforces expiry; no wall-clock timestamp is sent.

Use NWListener/NWConnection with TLS 1.3, ALPN `openminis-prototype/1`, no early data/resumption. Bind only the selected existing address; disappearance stops listener and channels. Rebind only that saved address. Phone pins the full SPKI hash before sending Hello or invitation proof. TLS proves host-key possession. Ignore certificate CA/hostname/date for this explicit pin policy; same-key reissue preserves the pin, a changed key refuses. Construct matching in-memory SecIdentity; never install a CA. Qualify exporter/certificate APIs on disposable loopback before a real endpoint.

Private P256 keys use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` on creation and `kSecAttrSynchronizable = false` in isolated services. On macOS every SecItem add/read/update/delete explicitly selects `kSecUseDataProtectionKeychain = true`; errors propagate without retrying the file-based Keychain. Injected query tests cover that selection. A fresh private key is created once; read failures do not rotate it. Signed Keychain lock/restart behavior remains unqualified; automated fixtures touch no production Keychain or account/signing state.

The signed Mac app uses its private default access group, authorized by `com.apple.application-identifier` and a matching embedded provisioning profile. A custom shared `keychain-access-groups` entitlement is unnecessary. Local physical qualification may use Apple Development signing with a development profile; Developer ID distribution needs its corresponding distribution profile. The iOS application identifier uses the spelling `application-identifier`. Record actual entitlement values, team, signing route and profile in the physical manifest and inspect the built artifacts. Unsigned compilation and fake-Keychain tests require none of that live provisioning.

### Resource and availability bounds

- At most two non-authenticated sockets total, including a pending local candidate. Ten seconds from acceptance through proof; local confirmation remains bounded by original 120-second window.
- Five failed proof attempts per invitation window; the fifth closes it. Valid claim consumes immediately. This is independent of normal authentication.
- Read/dispatch serially, no detached task per frame. Queue at most one frame per connection (`N <= 4096`, at most 4100 bytes including length); ten-second send deadline closes slow readers. Do not enqueue a second response behind a pending one.
- Initial physical experiment requires externally configured Tailscale policy allowing only the participating phone to reach the chosen Mac port. The apps do not configure that policy. Two reachable hostile clients can still starve this pool; no general DoS protection is claimed.
- Logs/diagnostic descriptions omit private keys, invitation text/QR/secret, exporter, proof/signature/nonces and comparison codes. Operational state/opaque IDs suffice.

## UI and evidence gates

Mac UI: explicit enable-hosting action each launch, endpoint, identity/readiness error, invitation/code, local confirmation/rejection and revoke. No execution/Stop controls. Phone UI: invitation text entry, optional scanner, comparison state, connected epoch, reconnect, local “Forget pairing” and “Commands unavailable.” Never display old-connection responses after a replacement. Foreground-only use; sleep/phone suspension causes visible disconnect, no wake/notification fallback. Closing the Mac window keeps enabled hosting until explicit disable/Quit; hosting never starts enabled on relaunch.

### Local pairing cleanup and fresh test installations

“Forget pairing” is a local probe action. It first invalidates the current connection/operation incarnation, cancels channels and clears comparison/tentative state; it never reconnects automatically. Then delete only the probe's paired-host item: `kSecClassGenericPassword`, service `org.openminis.prototype.controller.hostpins.v1`, account `paired-host`, non-synchronizable, in the app's default private access group. `errSecItemNotFound` is an idempotent success; other errors leave the probe disconnected with an explicit failure and no claim that persistence was cleared.

Keep the phone identity private key and every Mac Keychain item. Mac-side authorization remains until separately revoked on the Mac. Only the MainActor probe model writes the paired-host record: validate its current connection incarnation and perform the synchronous save/delete with no awaited gap. Thus a delayed authentication completion cannot restore a forgotten pin. A new enrollment requires explicit user action and local Mac confirmation; an existing saved pin is never overwritten by tentative data.

For repeatable physical cases, the Mac accepts the local launch option `--prototype-installation <uuid>`. The UUID must be nonzero and canonical lowercase; reject malformed, duplicate or missing values. It selects `<ApplicationSupport>/OpenMinisPrototype/installations/<uuid>`; without it use the `default` leaf. The application-support root is injected in automated fixtures. This option never comes from a peer or invitation, selects no arbitrary path and grants no network or execution authority. Hosting still starts disabled.

A later approved physical manifest records the exact installation UUID and resolved private directory. To repeat a consumed/revoked case: explicitly disable/Quit the prior host and close its owner, preserve that directory and lock for evidence, invoke Forget pairing on the phone, then launch the Mac with a new unused installation UUID. Load the existing isolated Mac identity key; the fresh store receives a new host ID/epoch and an unenrolled slot. The user supplies its new invitation and confirms the code locally. No old store is reset, migrated or deleted; its revoked slot stays revoked. Neither reinstalling an app nor deleting all Keychain items is a reset procedure. These real Keychain/device actions require the later bounded request; nothing is performed by this document.

| Gate | Required evidence | Excludes |
| --- | --- | --- |
| A source/automated | Fixed wire/golden vectors, clean-store byte preservation, queue/lease/revocation races, injected Keychain, disposable TLS loopback, unsigned standalone builds, independent review. | Signed launch, real Keychain, Tailscale/device acceptance. |
| A physical, later bounded request | Exact signed Mac/iPhone artifacts and profiles, cellular plus external Tailscale policy, possible firewall prompt, pin/exporter behavior, enrollment race/expiry/lost ACK, reconnect/revoke/address loss, scoped Forget/fresh-installation procedure, real Keychain lifecycle and log inspection. | Command/process/storage-crash qualification. |

This document and its plan authorize no builds/tests/dependency installs, signing, device installation, Tailscale changes, real Keychain writes, firewall responses or privacy prompts. Implementation and its disposable automated checks require the next explicit implementation request. Signed physical work requires its own bounded manifest/request. Do not commit/push/publish these drafts without instruction.

## Later execution roadmap — design gates only

Before adding any command route, write and review a separate execution design/plan that settles:

| ID | Required decision/evidence before implementation |
| --- | --- |
| B1 | Execution schema/compatibility and actual crash recovery; preserve unsupported bytes. No automatic v1 migration promise. |
| B2 | Exact script/approval/event and helper HELLO/GO formats, state transitions and one-shot launch authority. Replayed/unknown commits never launch. |
| B3 | Explicit periodic owner-queue heartbeat during quiet work; independent helper watchdog expiry, host cancellation latch and late-GO fence. A quiet 900-second command must not expire merely for lacking journal traffic. |
| B4 | Output placement plus aggregate journal/output budgets and admission headroom. Per-command 16 MiB alone is insufficient; do not invent history pruning to evade a startup cap. |
| B5 | Supported descendant model and sufficient absence evidence. Bounded drain/tool reporting differs from slot release; unresolved managed work blocks new execution. Markers cannot prove arbitrary escaped-child absence. |
| B6 | Cancellation/GO synchronization and truthful unknown outcomes for an already-dispatched action. Never promise zero post-request starts. |
| B7 | Startup reconciliation independent of database existence; crash windows, current signed native evidence and physical cellular qualification before production extraction. |

[Schema #2](https://github.com/jaylaney/OpenMinis/issues/2), [API boundary #3](https://github.com/jaylaney/OpenMinis/issues/3), and [storage executor #4](https://github.com/jaylaney/OpenMinis/issues/4) receive only the bounded status work described here; do not close them as fully qualified. [SQL cleanup #5](https://github.com/jaylaney/OpenMinis/issues/5) and [native durability #6](https://github.com/jaylaney/OpenMinis/issues/6) remain separate. The earlier 69-case foundation evidence is historical, not a result for this proposed code.

## 2026-11-03 review dispositions

The [review](2026-11-02-remote-execution-prototype-design-review.md) remains an unchanged historical snapshot.

| Finding | Revision |
| --- | --- |
| 1 — Mac Keychain | Explicit data-protection selection/query tests; default private app entitlement and matching profile are signed-manifest requirements. |
| 2 — Repeatable pairing | Local scoped Forget action and fresh local Mac installation UUID; existing revocation and host identity checks remain intact. |
| 3 — Finder metadata | Exact validated `.DS_Store` exception; recovery companions and other unknown entries still refuse. |
| 4 — Firewall | Manifest records policy, possible alert and authorized response; no unconditional prompt or automatic firewall change. |
| 5 — Unenrolled revoke | UI disabled; direct call clears pending enrollment, throws notEnrolled, leaves store unchanged and bridge fenced. |
| 6 — Bundle IDs | DNS ownership is not a requirement; availability/final IDs are verified before registration/signing. |

## Source references

- [SQLite hot-journal recovery](https://www.sqlite.org/lockingv3.html#dealing_with_hot_journals): normal opening can mutate before schema validation; rejecting all companions narrows support deliberately.
- [SQLite file-format version bytes](https://www.sqlite.org/fileformat.html#file_format_version_numbers) and [read-only WAL rules](https://www.sqlite.org/wal.html#read_only_databases): reject WAL rather than assuming read-only access prevents companion writes.
- [Commitment rationale for short authentication strings](https://www.rfc-editor.org/rfc/rfc6189.html#section-4.4.1.1): fresh post-commitment material prevents choosing a key against an already known comparison target; this application protocol is separately reviewable.
- [Contextual TLS exporter](https://developer.apple.com/documentation/security/sec_protocol_metadata_create_secret_with_context(_:_:_:_:_:_:)) and [SecIdentityCreate](https://developer.apple.com/documentation/security/secidentitycreate(_:_:_:)): API availability is not interoperability proof.
- [X509 1.17.0 manifest](https://github.com/apple/swift-certificates/blob/1.17.0/Package.swift): candidate dependency, exact compatible resolved graph is an implementation qualification result.

- [Mac Keychain implementations and provisioning](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains) and [Keychain access groups](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps): explicitly select the Mac data-protection implementation and authorize the private app access group.
- [Updating and deleting Keychain items](https://developer.apple.com/documentation/security/updating-and-deleting-keychain-items): deletion matches only the specified item; do not use a class-wide reset query.
- [Apple code-signing identifier guidance](https://developer.apple.com/forums/thread/811970): reverse-DNS formatting does not require domain control.
- [macOS firewall settings](https://support.apple.com/en-gb/guide/mac-help/-mh11783/mac): automatic allow policies mean an alert is conditional. The physical manifest records applicable policy and permitted response without disabling the firewall.
