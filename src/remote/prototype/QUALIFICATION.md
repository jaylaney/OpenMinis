# Authenticated-status qualification

This record covers the [status contract](../../../docs/superpowers/specs/2026-11-02-remote-execution-prototype-design.md)
and [plan](../../../docs/superpowers/plans/2026-11-02-remote-execution-prototype.md).
Commands are permanently unsupported. No helper, Stop, process, provider, sync or
production integration is qualified here. Parent execution gates B1–B7 remain
separate. This increment addresses bounded parts of issues #2–#4; work for
#5/#6 stays out of scope. No issue closure is performed.

## Revision and evidence classes

Baseline: `fcb9bb8f57cfd7241c01e22bdd87769f91364e7d`. The integrated implementation
is identified by the source fingerprint below; the baseline is not its artifact
revision. Final source fingerprint:
`bef8f9f29bedc052d83792bf6a9871bdafe9ff74626d8dc5a83e43287a6b14dd`
(76 source/test/project/pin/root-ignore files; excludes documentation, caches and
user state; `/private/tmp/openminis-pr7-r1-final-source-manifest.json`). Earlier 177-, 181-, 186- and 197-case/build reports are
historical. Current evidence covers the approved PR #7 local-policy/lifecycle,
confirmation-outcome and enrollment-phase fixes; earlier records are retained. No fixture, source graph or unsigned build establishes
signed deployment, physical readiness or power-loss durability.

| Class | Meaning |
| --- | --- |
| Source | Read-only inspection of current manifests, imports and implementation. |
| Automated | Production paths exercised by disposable fixtures, with injected IO explicitly identified. |
| Native loopback | Current-host Network/Security TLS with ephemeral in-memory identities and loopback sockets. |
| Unsigned artifact/link | Compilation and actual binary/link inspection, without launch/install. |
| Review | Fresh independent read-only whole-branch review. |
| Signed/physical | Later bounded request, actual signatures/profiles, Keychain and participating devices. |

## Gate A commands and current results

Commands run from the repository root, serialized by the primary. No qualification
script or documentation-only test is added.

```sh
xcrun swift test --package-path src/remote --scratch-path /private/tmp/openminis-status-package
xcodebuild -project src/remote/prototype/RemoteExecutionPrototype.xcodeproj -scheme RemoteHostPrototype -destination 'generic/platform=macOS' -derivedDataPath /private/tmp/openminis-status-mac CODE_SIGNING_ALLOWED=NO build
xcodebuild -project src/remote/prototype/RemoteExecutionPrototype.xcodeproj -scheme RemoteControllerProbe -destination 'generic/platform=iOS' -derivedDataPath /private/tmp/openminis-status-ios CODE_SIGNING_ALLOWED=NO build
git diff --check
```

| Evidence | Revision | Result | Class / record |
| --- | --- | --- | --- |
| Full unfiltered command above | Final fingerprint | PASS, exit 0 | Automated; `/private/tmp/openminis-pr7-r1-full-tests.log` |
| Mac command above | Same | PASS, exit 0, BUILD SUCCEEDED | Unsigned artifact; `/private/tmp/openminis-pr7-r1-mac-build.log` |
| iOS command above | Same | PASS, exit 0, BUILD SUCCEEDED | Unsigned artifact; `/private/tmp/openminis-pr7-r1-ios-build.log` |
| `git diff --check` | Final source and documentation | PASS, exit 0 after final doc update | Source hygiene; primary-owned |
| Fresh whole-branch review, baseline → pre-expiry-fix working tree | `cf96268b…` | PASS with one Minor M1, zero Critical/Important | Review; `/private/tmp/openminis-status-final-whole-branch-review.md` |
| Independent scoped M1 fix re-review | Historical `c254ab78…` | PASS; M1 addressed, no introduced finding | Review; `/private/tmp/openminis-status-final-fix-rereview.md` |
| Fresh whole-branch PR #7 fix review | Historical `9061791a…` | One Important I1; changes required | Review; `/private/tmp/openminis-pr7-fixes-whole-branch-review.md` |
| Independent scoped I1 correction re-review | Current `bef8f9f2…` | PASS; I1 addressed, no introduced finding | Review; `/private/tmp/openminis-pr7-r1-rereview.md` |

The fresh primary run reports **202 XCTest cases, zero failures, one expected
parent-only `StateDirectoryUmaskTests.testUmaskChildFixture` skip**. The original
69 legacy cases remain, plus 133 new cases. Suite totals: Core 85, public API 20,
Wire 7, Transport 32 (including 9 native TLS and 13 pump cases), Host 28,
Certificates 2, HostModel 15, Probe 13. All native TLS tests executed; no compiler
warnings/errors. The Mac build has only the known no-AppIntents metadata warning; the
incremental iOS build has no warnings. No skipped gate counts as passing.

## Requirement matrix

Each named test below is selected by the passing full command above, not a
replacement filtered run. PASS is limited to the stated evidence class.
`R` means the final source fingerprint above, with artifact hashes where applicable.

| ID | Exact named test / inspection | Revision | Result | Class |
| --- | --- | --- | --- | --- |
| A1 | `HostModelTests` (including `testIdleInvitationExpiresAutomaticallyFromOwner`, `testLateAutomaticPresentationCannotClearReplacementWindow`), `ProbeModelTests`; package/project/import and actual phone link inspection below | R | PASS | Automated + source/link |
| A2 | `PinnedTLSTests.testPinPolicyAndEndpoint`, `testSelectedAddressLossClosesAndRebindsOnlySavedAddress`, `testInjectedAddressLossStopsNativeListenerAndAcceptedChannels` | R | PASS | Injected address policy + native loopback shutdown |
| A3 | `AuthTranscriptTests`, `PeerAuthenticationTests`, `PinnedTLSTests.testExporterInteroperatesWithLiteralNativeLabelAndContext`, `HostBridgeTests.testProofVerifiedBeforeOwnerAndRechecked` | R | PASS | Automated + native loopback |
| A4 | `StatusEnrollmentTests.testDelayedProofAndConfirmDisconnectOrder`, `StatusRevocationTests`, `HostBridgeTests.testDirectUnenrolledRevokeLeavesFenceDisabled` | R | PASS | Automated |
| A5 | `StatusEnrollmentTests.testOneClaimPostFixationNonce`, `AuthTranscriptTests.testComparisonBindsClaimAndPostFixationNonce`, `ProbeModelTests.testNoSASBeforeOwnAcceptedDigest`, `testComparisonDescriptionsRedactSecrets` | R | PASS | Automated |
| A6 | `StatusOwnerTests`, `StatusLeaseTests`, `StatusSchemaTests.testExactReferenceSchemaAndData`, `StatusPreflightTests.testOwnershipAndLegacyGuard` | R | PASS | Automated |
| A7 | `StatusPreflightTests`, `StatusSchemaTests.testValidatorNeverWrites`, `testBackupExclusionBeforeReadiness` | R | PASS | Disposable filesystem / injected backup boundary |
| A8 | `HostBridgeTests.testStatusOnlyAllowlist`, `WireEncodingTests.testExactGoldenFrames`; phone graph/link inspection | R | PASS | Automated + source/link |
| A9 | `StatusRevocationTests.testRevocationStorageFaultsFenceOwner`, `HostBridgeTests.testRevokeFailureAndLateDelivery`, `UnknownCommitOutcomeTests` | R | PASS | Automated, selected storage faults injected |
| A10 | `PrototypeKeyStoreTests`, `ProbeModelTests.testProductionStoreSavedPairingWithMissingKeyDoesNotCreate`, `testProductionStoreProofCannotCreateIdentity`, `testForgetCancelsPendingConnectAndDiscardsLateReadyChannel` | R | PASS | Injected SecItem/channel IO; real policy/proof paths |
| A11 | `ConnectionPumpTests.testTwoPendingIncludesCandidate`, `testDeadlinesAndBackpressure`, `StatusEnrollmentTests.testWindowFailureAndDeadlineLimits` | R | PASS | Automated; external ACL remains physical gate |
| A12 | Both exact unsigned build commands, actual signature/link inspection and separate manifest below | R | PASS | Unsigned artifact + classification |

A7 foreign-owner metadata evidence is bounded: `testArtifactValidatorRejectsForeignEffectiveOwner`
passes an actual fixture `stat` with a substituted UID through the real shared
validator. Nonroot tests created no genuinely foreign-owned on-disk file; this
is not full native foreign-owner qualification. Integrated metadata fixtures
establish that metadata is routed through that validator.

M1 was the idle expired-invitation display. HostModel now refreshes owner
presentation automatically while secrets are displayed. Its one-second wait is
a presentation cadence, not a second policy deadline; stale wakes/reads are
fenced. Five new regressions include real-Core expiry and lifecycle coverage.
The full review covered the earlier snapshot; the scoped fix review covers only
this subsequent change and found M1 addressed with no introduced Critical,
Important or Minor finding. No second whole-branch review of the current hash
is claimed. That earlier review chain passed for its historical snapshots. The fresh PR #7
whole-branch review found I1; its correction passed independent scoped re-review
at the current fingerprint. Current automated/unsigned verification also passes.
No second whole-branch review at the current hash is claimed. Signed/physical
acceptance remains separate.

The approved PR #7 corrections use the same owner and schema. Explicit local
policy load is existing-only, validates the retained host identity, and invokes
no transport credential/certificate/listener setup. Missing/zero-byte input
cannot create a policy, epoch, identity, state leaf or main file. A retained
failed owner requires explicit Close; local refresh/Enable cannot silently
replace it. Storage failure while listener startup is awaiting completion obeys
the same rule. A healthy network-start failure leaves local policy readable. A local-policy load for a different selected directory is refused until Close. Owner
presence remains visible independently from network readiness.

| Correction | Named regression in the full run | Evidence class |
| --- | --- | --- |
| Offline policy/revoke | `StatusSchemaTests.testExistingOnlyOpenRefusesFreshWithoutCreation`, `testExistingOnlyOpenLoadsEnrolledPolicy`; `HostBridgeTests.testOfflineExistingPolicyLoadAndRevokeWithoutTransportSetup` | Disposable filesystem/real Core, injected transport-call spies |
| Retained owner Close | `HostBridgeTests.testStorageReadFailureDisablesAndRetainsOwner`, `testCloseDuringLocalPolicyOpenDiscardsLateOwner`; `HostModelTests.testExplicitLocalLoadAllowsOfflineRevokeAndClose` | Real Core/lock with injected failure/open barriers; model fixture |
| Commit/delivery separation | `HostBridgeTests.testLostCommitAckUsesNormalAuth`, `testCommittedConfirmationSurvivesCloseDuringHeldCommit`, `testConfirmationUsesCommittedSnapshotAndLaterReadinessFailureRemainsError`, `testConfirmationCommitFailureAndUnknownOutcomeStayErrors`; `HostModelTests.testCommittedNoticeSurvivesReadinessFailure` | Real transactions with selected native result/send/queue faults injected |
| Full owner enrollment phase | `HostModelTests.testEnrollmentGateUsesOwnerPhaseIncludingHeldCandidateSend`; `HostBridgeTests.testCandidatePublicationWaitsForSendCompletion` | Owner-backed bridge plus controlled model/send fixtures |
| Selected installation | `HostBridgeTests.testLocalPolicyLoadRefusesDifferentSelectedDirectoryUntilClose` | Two real disposable stores/locks with distinct epochs |
| Startup owner retention | `HostBridgeTests.testPublishedOwnerFailureDuringListenerStartRemainsUntilClose`, `testCloseDuringHeldListenerStartCannotRetainOrReviveOwner`; `HostModelTests.testEnableErrorRefreshesRetainedOwnerAndReadiness`, `testCloseDiscardsHeldEnableErrorResourceRefresh` | Held listener startup, real Core/error/lock, injected external IO and model barriers |

Confirmation returns the known committed snapshot after COMMIT. A subsequent
lost connection/send reports uncertain acknowledgement delivery rather than a
failed enrollment. Core/unknown-commit failures stay errors/fenced, and a later
readiness failure remains visible alongside a known committed notice. Native
send completion does not establish phone receipt or persistence. Owner phase
keeps Open enrollment disabled during a fixed claim even before its comparison
is published. Core retains all deadline/authorization decisions.

Queue sentinels establish responsiveness under deterministically blocked owner
jobs, not a performance benchmark. SQLite DELETE/EXTRA/fullfsync readback and
ordinary close/reopen do not prove physical flushing or power-loss survival.
Status accepts only fresh or validated clean rollback stores; every recovery
companion is refused untouched. A crash journal can block reopen. No migration,
reset, journal deletion or silent fresh-state fallback is qualified.

The controller permits one outstanding request; host dispatch is serial.
Same-read pipelining and observable response preemption are refused. Separate
native receives cannot universally expose a malicious peer's original send
timing; frozen wire v1 supplies no stronger timing claim.

## Target, dependency and linked-artifact evidence

Read-only source inspection: `Package.swift`, `Package.resolved`, the standalone
`project.pbxproj`, `prototype/iOSProbe/*.swift`, and imports under
`Sources/RemoteControllerProbeModel` / `Sources/RemotePrototypeTransport`.
Result **PASS (source only)**: phone app imports its model; model → Wire/Transport,
Transport → Wire. Core/Host/Certificates/X509 are outside that production closure.
The macOS-only Certificates dependency in Transport **tests** does not enter it.
Final actual link/symbol/plist inspection also **PASS (unsigned link only)**:
`RemoteControllerProbe.LinkFileList` has exactly `App.o`, `ProbeView.o`,
`RemoteControllerProbeModel.o`, `RemotePrototypeWire.o`,
`RemotePrototypeTransport.o`. No Core/Host/Certificates/X509 object appears.
`nm` exits 0 for both phone launcher and `RemoteControllerProbe.debug.dylib`,
with no symbols from those excluded modules; the debug dylib contains expected
model/Wire/Transport symbols. `otool -L` on launcher and debug dylib exits 0 and
shows system/Swift frameworks, with no SQLite or excluded package library.
Inspecting the debug dylib matters because the launcher delegates to it.
A package project named RemoteExecutionCore does not imply its Core target is linked into the phone.

| Package | Version | Resolved revision | License |
| --- | --- | --- | --- |
| swift-certificates | 1.17.0 | `133a347911b6ad0fc8fe3bf46ca90c66cff97130` | Apache-2.0 |
| swift-crypto | 4.5.2 | `da9d28d69ebe3894b18376c8f2395c2f37b8448f` | Apache-2.0; vendored notices apply |
| swift-asn1 | 1.7.4 | `917b472dbe53ba699cbb0495f9a95a084bc6364d` | Apache-2.0 |

Task 8 inspected the exact upstream manifests/licenses: tools 6.1 is required by
Crypto/ASN1; root tools 6.0, Swift 6 language and macOS 13/iOS 16 floors remain.
Installed Swift 6.4.2 compiles this graph; no Swift 6.0 compiler compatibility is
claimed. Retain upstream LICENSE/NOTICE obligations for any future distribution,
including BoringSSL notices; nonselected CXKCP sources have their own notices.
Final root/workspace lock files are byte-identical (SHA-256
`24dfd0ac914533eb09fac6cbb7c493f6fd441d796f489eb782d8b9eba908a950`);
both DerivedData `SourcePackages/workspace-state.json` checkout revisions match
all three pins above.

Native loopback tests exercise actual TLS 1.3 pinning, same-key certificate
reissue, wrong pin, exporter interoperability and protocol rejection on this Mac.
Endpoint presence/loss uses injected address inventory, including stopping an
actual loopback listener. These do not demonstrate cellular routing, actual
tailnet binding, firewall behavior or a physical phone.

Inspected final artifact locations (not a launch instruction):

- Mac: `/private/tmp/openminis-status-mac/Build/Products/Debug/RemoteHostPrototype.app`.
- iOS: `/private/tmp/openminis-status-ios/Build/Products/Debug-iphoneos/RemoteControllerProbe.app`.

Final plist reads confirm Mac `org.openminis.prototype.host`, minimum 13.0,
SDK macosx27.2; iOS `org.openminis.prototype.controller`, minimum 16.0, SDK
iphoneos27.2. Read-only `codesign -dv --verbose=2` returns 0 for the universal
Mac artifact: `adhoc,linker-signed`, TeamIdentifier not set, Info.plist not bound,
no sealed resources. It returns 1 for iOS: `code object is not signed at all`.
No CodeSign mutation was performed. `CODE_SIGNING_ALLOWED=NO` allows this Mac
linker metadata; it is not team/profile signing or signed-native acceptance.

SHA-256 of actual final unsigned files (not a complete bundle digest):

| File relative to its app | SHA-256 |
| --- | --- |
| Mac `Contents/MacOS/RemoteHostPrototype` | `069255563a30e618a3424ac5e24939c7a9ebe290fa3bea9ab6010456f0f97637` |
| Mac `Contents/MacOS/RemoteHostPrototype.debug.dylib` | `e5abf1c86267f962f9e8eb8a4f3382f46f3254cd7052d0307b8f9ee3ed60396a` |
| iOS `RemoteControllerProbe` | `86844870e59914a98c7ecac662dfab282cfd5c2f8819541b3894d7fead849256` |
| iOS `RemoteControllerProbe.debug.dylib` | `eb570169288dac85a25dbffdd4e34415b6a60eed07f2937758f43ed80561fc2e` |

Inspection used Python `plistlib` / `hashlib` / JSON reads for the exact paths
above; native commands were `codesign -dv --verbose=2 <app>`, `otool -L <binary>`
and `nm <binary>`, applied also to the debug dylibs. No artifact was executed.
The platform's no-AppIntents metadata-extraction warning is expected
for these apps; no dummy AppIntents dependency is added.

## Signed physical manifest template — all NOT RUN

This is a concrete template for a later **separately authorized bounded request**,
not permission to sign, register, install, launch, change policy, delete Keychain
items or conduct experiments. Keep private values in the later private record;
committed paths use placeholders, never a personal username.

| Field | Value / evidence required | Result |
| --- | --- | --- |
| Source / dependencies | Final fingerprint above; exact pins above; recheck for the physical build | NOT RUN |
| Gate A artifact hashes | Current unsigned file hashes above; record physical signed artifact hashes separately | NOT RUN |
| Registered IDs | Proposed `org.openminis.prototype.host` / `org.openminis.prototype.controller`; verify availability under selected team before registration; no domain ownership requirement | NOT RUN |
| Signing route / team | `<team-ID>`, identities; local Mac Apple Development + development profile, or Developer ID + corresponding profile for that route | NOT RUN |
| Mac signature/profile | Actual private default group, `com.apple.application-identifier`, entitlements and matching embedded profile authorization; no custom shared group | NOT RUN |
| iOS signature/profile | Actual `application-identifier`, entitlements, matching embedded profile and device authorization | NOT RUN |
| Platforms / hardware | `<Mac model, OS build>`, `<iPhone model, iOS build>`; Xcode/Swift versions | NOT RUN |
| Endpoint / network | `<selected literal tailnet IPv4>:<port>`; awake Mac, foreground phone, cellular route; externally enforce participating-phone-only reachability ACL | NOT RUN |
| Firewall | Applicable Mac incoming policy; record conditional alert and explicitly authorized response. Eligible signed software may be allowed automatically; blocked connection remains failed/blocked | NOT RUN |
| Existing identity | `<isolated host identity tag/pin>` and retained controller identity; never export private key bytes | NOT RUN |
| Old installation | `<old UUID>`, `<ApplicationSupport>/OpenMinisPrototype/installations/<old UUID>` resolved fixed leaf; preserve database, lock and revocation | NOT RUN |
| Fresh installation | `<explicit unused UUID>`, `<resolved fixed leaf>`; pass `--prototype-installation <UUID>` only after explicit selection | NOT RUN |
| Scoped phone Forget | Generic password, service `org.openminis.prototype.controller.hostpins.v1`, account `paired-host`, non-sync, default private group; preserves identity and unrelated items | NOT RUN |
| Logs / evidence | `<private redacted evidence location>`, timestamps and artifact hashes; no invitation secret, proof, code, key or transcript dump | NOT RUN |

For repeat consumed/revoked cases: explicitly disable/Quit/close the old owner;
retain its leaf and lock; perform the authorized scoped phone Forget; explicitly
select a new unused Mac installation UUID; verify distinct host ID/epoch and
unchanged isolated private identity; then use a new invitation and local Mac code
confirmation. Forget changes no Mac policy. Do not reinstall as a reset, erase
Keychain classes, delete a database, clear a revocation or silently choose fresh
state after refusal. No installation is created or deleted by this record.

| Case / requirement | Finite observation to record under later request | Result | Class |
| --- | --- | --- | --- |
| P1 / A2–A3 | Cellular pinned TLS 1.3 and contextual exporter to exact saved tailnet endpoint | NOT RUN | Signed/physical |
| P2 / A3 | Wrong-key rejection; same-key certificate reissue retains pin acceptance | NOT RUN | Signed/physical |
| P3 / A4–A5 | Two-phone enrollment race: one immutable claim, own accepted code, local confirmation only | NOT RUN | Signed/physical |
| P4 / A4–A5,A11 | Invitation expiry, fifth failure, replay and expired candidate refusal | NOT RUN | Signed/physical |
| P5 / A4,A10 | Lost commit ACK then normal authentication using retained identity/pin | NOT RUN | Signed/physical |
| P6 / A4,A9 | Disconnect/reconnect, local revoke, late response fencing and refused subsequent reconnect | NOT RUN | Signed/physical |
| P7 / A10 | Exact scoped Forget and explicitly selected fresh-installation enrollment, old revocation unchanged | NOT RUN | Signed/physical |
| P8 / A2 | Selected address loss closes listener/channels; only same saved address may rebind | NOT RUN | Signed/physical |
| P9 / A10 | Actual data-protection Keychain authorization, lock and app/host restart; unavailable keys refuse without replacement | NOT RUN | Signed/physical |
| P10 / A5,A12 | Inspect actual redacted app/system logs and secret-free public diagnostics | NOT RUN | Signed/physical |
| P11 / A4,A9–A10 | With network hosting disabled, explicitly load existing local policy, revoke without listener setup, Close/reopen and verify retained revocation and load-only Keychain behavior | NOT RUN | Signed/physical |

Signed/physical acceptance, minimum-OS runtime, sleep/foreground/window behavior,
backup-restore behavior, power-loss durability and general crash recovery remain
unqualified. No command/helper/process evidence belongs to this manifest.
