# RemoteExecutionCore and authenticated-status prototype

This Swift 6 package contains the legacy SQLite admission foundation and a
separate status-only profile with standalone Mac host and iPhone probe targets.
The prototype supports enrollment, pinned TLS, authenticated status, reconnect
and local revocation. Commands are permanently unsupported by this profile;
there is no helper, Stop, provider, sync or production app integration.

See the [approved status contract](../../docs/superpowers/specs/2026-11-02-remote-execution-prototype-design.md),
[implementation plan](../../docs/superpowers/plans/2026-11-02-remote-execution-prototype.md)
and [qualification record and physical manifest template](prototype/QUALIFICATION.md).
The standalone project is `prototype/RemoteExecutionPrototype.xcodeproj`, with
`RemoteHostPrototype` and `RemoteControllerProbe` schemes. Building these targets
is separate from signing, launching, installing or physical qualification.

The root manifest uses Swift tools 6.0 and Swift 6 language mode, with macOS 13
and iOS 16 deployment floors. The exact dependency graph requires tools 6.1
(swift-certificates 1.17.0, swift-crypto 4.5.2, swift-asn1 1.7.4); current
qualification uses installed Swift 6.4.2, not a Swift 6.0 compiler claim.

## Status-only profile

`StatusOnlyHost.open` submits initialization and all owner work to one dedicated
serial queue, validates identity against the committed store, and publishes
handles only after backup-exclusion readback. Transport depends only on Wire;
the phone adds its controller model and system frameworks, excluding Core, Host
and Certificates/X509. Source and unsigned link evidence do not establish
physical runtime or signed Keychain acceptance.

Status uses its own installation leaf, the stable `admission.lock`, and the same
`admission.sqlite3` filename under a mutually exclusive open profile. Only fresh
or validated clean rollback-format OMST v1 stores are accepted. Every recovery
companion, including an empty rollback journal, is refused untouched; the narrowly
validated `.DS_Store` exception is metadata only. A crash journal can therefore
block reopen. Keep the store and lock for diagnosis: there is no migration,
reset, deletion, recovery or automatic fresh-installation workaround. A legacy
opener refuses OMST before writable open; legacy behavior otherwise remains
unchanged.

The controller has one outstanding request and the host dispatches serially.
Observable same-read pipelining and response preemption close the connection;
frozen wire v1 cannot universally detect peer-send timing across separate native
receives. This is not an arbitrary malicious-peer timing guarantee. Public
comparison diagnostics are redacted. Host presentation automatically refreshes
while an invitation or candidate is visible, using owner policy rather than a
second UI expiry deadline.

The status profile adds native TLS, enrollment, Keychain adapters, async ownership,
backup gating and prototype UI. The remaining sections describe the **legacy
admission profile** and its integration obligations. Their deferred transport,
backup and executor statements apply to that profile.

Run the package tests from the repository root:

```sh
swift test --package-path src/remote --scratch-path /private/tmp/openminis-remote-admission-build
```

The fixtures use unique temporary directories and opaque synthetic payloads.
Legacy fixtures exercise SQLite persistence, delayed delivery, leases and recovery
without network peers or user databases. Status fixtures additionally exercise
disposable native TLS loopback with ephemeral identities; injected Keychain and
address-policy tests do not access real paired devices or Keychain items.
ACL fixture setup invokes system chmod only
within disposable temporary directories; it does not qualify managed command
execution or process supervision. The internal instance-owned `SQLiteNative`
boundary defaults to real SQLite. Fault fixtures simulate selected native
`column_text`/`step` results while exercising production row mapping, transaction
handling and actor APIs; they do not claim genuine native OOM or rollback-I/O
injection. Native SQL NULL, ordinary rollback and SQLITE_FULL automatic rollback
fixtures continue to use real SQLite.

## Private state and storage errors

Supply a dedicated host state leaf below an existing stable, trusted parent.
Initialization creates a missing leaf and normalizes only that newly created leaf to mode 0700, independently of the process umask. An existing leaf or an EEXIST result is never normalized. Before opening the lock or
SQLite, it rejects a symbolic-link leaf, non-directory, foreign owner, missing
owner rwx mode bits, any group/other mode permissions, and extended ACL allow entries
(including inherited grants). A successful native security inspection accepts an
absent ACL or deny-only ACL; inspection failures are refused. Owner access here
means mode bits: a deny ACL can still cause a fail-closed EACCES when storage is
opened. The core does not claim an effective-access or native ACL qualification.
Existing leaves, parents, contents and ACLs are never silently chmodded, stripped or deleted.
Host provisioning must explicitly repair older permissive state directories
while preserving their journal and storage epoch. These ordinary POSIX/ACL checks
do not isolate against a hostile process running as the same user and do not
make a shell sandbox. Native filesystem/platform qualification remains required.

The requested path must have a named leaf and no `.` or `..` components. Only its
trusted parent is canonicalized with POSIX `realpath`, preserving ordinary macOS
parent aliases; the original leaf is checked without following it. Lock and
database opens use this single prepared path with `O_NOFOLLOW` and
`SQLITE_OPEN_NOFOLLOW`. Before either opens, existing `admission.lock`,
`admission.sqlite3`, and SQLite `-journal`, `-wal`, `-shm` companions must be
regular files owned by the effective user with one hard link. The opened lock
descriptor is checked too. Unsafe artifacts are rejected without repair. These
are cooperative filesystem checks below a stable parent, not hostile same-user
race isolation.

New lock and main-database files are exclusively created and normalized through
their new descriptors to mode 0600, preserving owner read/write even when the
process umask removes those bits. Production code never changes the process
umask. Main-file creation occurs while the ownership lock is held; SQLite opens
the prepared file without a fallback to default-permission creation. Existing
files are opened without normalization: writable 0644 files remain acceptable,
and existing read-only files require explicit host provisioning rather than
automatic repair. This is new-file availability handling, not strict artifact
mode enforcement or a migration policy.

SQLite uses `journal_mode=DELETE`, `synchronous=EXTRA` (native level 3), and
`fullfsync=ON`. Initialization verifies effective DELETE mode, synchronous
EXTRA (3), and fullfsync ON (1) before journal initialization and refuses a
missing or unexpected result with a structured storage error. The synchronous
and fullfsync setters return no row, so their effective values are queried
separately. A fullfsync readback verifies the requested flag; it does not qualify
successful native F_FULLFSYNC, hardware flushing or power-loss behavior. These are defensive policy
checks, not evidence of a reproduced silent WAL-mode failure. EXTRA requests
the directory synchronization after deleting the
rollback journal; FULL alone does not request that point, and fullfsync selects
the synchronization method rather than adding it. The regression reads native
PRAGMA values and performs a real transaction/close/reopen. It establishes the
configured durability policy and ordinary persistence, not power-loss behavior;
genuine power-loss/filesystem qualification remains unperformed. See SQLite's
[synchronous documentation](https://www.sqlite.org/pragma.html#pragma_synchronous).

Fresh-directory durability is a specific pending qualification case. After
creating the state leaf, the core does not explicitly synchronize the canonical
parent directory. SQLite's journal-directory synchronization alone does not
establish persistence of that parent entry. Qualify a power loss after the first
acknowledged commit in a newly created leaf, including disappearance of the leaf
and resulting fresh epoch. The Darwin/filesystem mechanism for synchronizing
that parent, including directory `F_FULLFSYNC` support and sufficiency, has not
been qualified. Startup process reconciliation is still required for fresh or
lost storage, as described below.

`JournalStorageError` is public and exposes a stable `kind` (`alreadyOwned`,
`sqlite`, `filesystem`, `invalidDirectory`, `invalidState`), diagnostic `message`,
optional SQLite primary/extended codes and optional POSIX code. Its localized
message is useful without parsing it to classify errors. SQLite diagnostics are
captured while the handle is valid. `JournalTransactionError` is a separate
public composite carrying `originalError` and `rollbackError`; both appear in its
localized diagnostic, even when the original cause is an `AdmissionError`.
Automatic SQLite rollback after a transaction-body error preserves its original cause. `AdmissionError` has
stable short payload-free localized case descriptions. A non-NULL SQLite column
whose text conversion fails throws its captured storage diagnostic immediately;
only native SQL NULL maps to an optional nil.

An explicit rollback failure makes that owner terminally unusable. Every actor
operation, including cached status, connection issuance, reads and administration,
throws the retained `JournalTransactionError` with both causes until the owner is
destroyed and storage reopened. It does not silently reset epochs, release the
ownership lock, expose uncommitted rows, or downgrade the composite to an ordinary
admission refusal. Reopening still applies the normal durable-state recovery
rules; process absence remains a separate host responsibility.

A failed `COMMIT` can report an error after its changes have taken effect. If
autocommit is enabled after that failure, the outcome is unknown: autocommit
does not prove rollback, and failed synchronization does not establish power-loss
durability. `JournalCommitOutcomeUnknownError` retains the `originalError` and
terminally fences every API, just as a failed rollback does, until destruction
and reopen. It does not invent a rollback cause or expose a stale cached status.
The lock remains held while that owner exists. A failed `COMMIT` that leaves the
transaction active retains the explicit-rollback path; successful rollback
leaves the owner usable. Reopen applies normal persisted-state recovery, without
authorizing replay or launch. The regression performs a real native commit and
then simulates its reported error; it does not inject a real VFS/disk failure.

## Admission and status

Create one `AdmissionCoordinator(directory:controllerID:)` per journal directory,
with exclusive ownership for its lifetime. A nonblocking exclusive OS lock on the
stable `admission.lock` file is acquired before opening SQLite and retained until
the connection closes, including initialization failures. Concurrent owners fail
with a storage error before changing journal state. Never unlink or replace the
lock file while a journal owner may exist. Initialization validates/binds the
configured controller in the same transaction before changing recovery state;
a wrong controller leaves persisted state untouched. The synchronous journal is
internal to the package, confined to that coordinator.

`connect(controllerID:)` returns an opaque `ConnectionLease` with no public
initializer. Replacing the connection invalidates the old lease. A rejected
foreign-controller connect leaves the valid lease intact. Submit and reconcile
validate the controller, current lease and storage epoch before synchronous
journal transactions, without an actor suspension between validation and commit. The
expected reconciliation epoch is also checked inside its journal transaction,
before looking up an existing record or writing an absence tombstone, matching
the transactional epoch fences for admission and settlement.

Each request ID has one durable disposition for its storage epoch. Matching
retries return that record; changed identity, metadata or payload conflicts are
rejected. `submit(_:over:)` returns `SubmissionResult(record:isReplay:)`:
`isReplay` is false only for a newly inserted decision and true for every existing
record, including an absence tombstone. Reconciliation still returns a
`RequestRecord`. Only `!result.isReplay && result.record.disposition == .admitted`
signals a new Start admission. An existing admitted record, including after
reopen, never authorizes another launch. This return marker is not a durable
process-execution claim: the host still needs its separately qualified durable
intent, launch and recovery protocol before executing processes.

An unknown-ID `reconcile(requestID:epoch:over:)` writes `rejectedAbsent` before
returning. This tombstone refuses all later content for that ID, including
delayed sends on a replacement connection and after reopening storage. Busy
rejections also remain terminal. A reset creates a new namespace, so IDs may be
used anew only with its new epoch.

`RequestRecord` describes admission or rejection. `admitted` means the run was
admitted, and `stopRequested` means a Stop was recorded. Neither establishes that
a command started, terminated or succeeded. Stop keeps the active slot occupied.
`status() throws -> AdmissionStatus` is a trusted host-internal snapshot; callers
use `try await coordinator.status()` so a terminal storage condition is visible.
Connection bootstrap uses
`status(over:)`, which validates the current controller lease without requiring a
known epoch. Trusted host lookup uses `runStatus(for:epoch:)`; connection lookup
uses `runStatus(for:epoch:over:)`, validating both the current lease and epoch.
There is no public bare-RunID lookup. Run lookup rejects an old epoch before
querying the run, so a reused ID cannot disclose replacement state. `RunRecord`
includes its verified epoch along with run state and any settled outcome. Only
explicit host settlement releases an active slot during normal operation. Late Stop requests
for another run cannot change the current run. Automatic Stop retry must never
resurrect a tombstoned or otherwise terminally refused ID. After a definitive
`rejectedAbsent` or other terminal refusal, first check that the same target still
needs Stop, then use a new Stop ID with the same epoch/session/run. A changed
epoch never silently retargets an old Stop. Receipt of `stopRequested` does not
prove termination.

Reopening unresolved work sets `recoveryRequired`: new Start requests receive
terminal `rejectedBusy` decisions, while matching run-scoped Stop
remains available. Reusing a refused ID stays rejected after recovery; an
explicit later Send needs a new ID. The host must verify
that recovered processes are absent before calling
`confirmRecoveredProcessesAbsent()`. That call records `interruptedUnknown` for
unresolved work and invalidates previous leases only if recovery actually changed.
Process absence is asserted when the call is made; an observed command exit does
not prove that the entire agent run completed. Recovery conservatively records
`interruptedUnknown` at run level. A later supervisor must separately retain any
observed tool-level evidence; recovered commands or agent loops never resume
automatically.
A no-op confirmation preserves the current lease. `reset()` requires no active or
recovery-blocked work, preserves controller binding, creates a fresh storage
epoch and invalidates previous leases. Old-epoch submissions, reconciliations
and settlements are refused. Lost storage likewise creates a new epoch.

## Host trust boundary and remaining qualification

An external authenticated host adapter must supply the configured controller ID,
authenticate and authorize its connection, hold exclusive journal ownership,
verify process absence, and serve the public actor methods through its chosen
transport. Controller IDs and leases here are local admission capabilities; this
core does not authenticate people, encrypt a channel or supervise processes.

`status()`, `runStatus(for:epoch:)`, `settle(runID:epoch:outcome:)`,
`confirmRecoveredProcessesAbsent()` and `reset()` are host-internal integration
APIs. Connection reads must use the lease-validated overloads. Host-internal APIs
must not be exposed as unauthenticated remote operations. The host must observe actual termination before settlement;
Stop acknowledgement alone is insufficient. Capture the storage epoch when the
run is admitted and pass that captured epoch to settlement. Connection leases
may change while a run continues, so settlement does not use a lease. An old-epoch
completion is rejected inside the journal transaction before any target-run
lookup or mutation, including when a new-epoch run reuses the same run ID.
Matching same-epoch duplicate settlements remain idempotent; contradictory
outcomes are rejected.

Before exposing any Start, the host must reconcile previously managed processes
and prove absence or keep admission blocked outside this core. This startup duty
also applies to fresh, lost or empty storage when `recoveryRequired` is false:
a new epoch and an empty journal cannot prove that no process survived.

Before service begins, the host must mark its state directory excluded from
backup and verify that policy. The legacy admission profile does not set that filesystem
attribute; the status profile gates readiness on its application and readback. Restore exclusion and fresh-epoch behavior still require native
qualification; backup restoration cannot be treated as already safe.

Pre-production host gates also include local controller replacement/revocation
that blocks admission, invalidates authority and cancels owned work; explicit
per-run controller ownership; and schema version/migration planning. This package
has a persistent single-controller binding, not an enrollment/revocation API or
a schema migration. Deleting the database is not a controller replacement
procedure. Its synchronous SQLite work also needs dedicated-executor performance
qualification before host integration; no dedicated executor is implemented for the legacy profile. The status profile
has a dedicated serial owner queue.

The status profile implements native TLS, authenticated transport, enrollment/key
management and standalone UI. External Tailscale configuration, signed Keychain
and physical-device qualification remain separate. Process supervision, commands
and parent execution gates B1–B7 remain deferred; status work advances only bounded
parts of issues #2–#4 and does not close them. Issues #5/#6 remain open. Gate 2
production extraction remains pending the parent design and qualification gates.
