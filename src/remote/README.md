# RemoteExecutionCore

A Swift 6 package for local, durable remote-execution admission decisions and
reconnect reconciliation, backed by real SQLite. There is no runnable host and
no production app integration in this increment.

Run the package tests from the repository root:

```sh
swift test --package-path src/remote --scratch-path /private/tmp/openminis-remote-admission-build
```

The fixtures use unique temporary directories and opaque synthetic payloads.
They exercise SQLite persistence, delayed delivery, leases and recovery without
network peers or user databases. ACL fixture setup invokes system chmod only
within disposable temporary directories; it does not qualify managed command
execution or process supervision. The internal instance-owned `SQLiteNative`
boundary defaults to real SQLite. Fault fixtures simulate selected native
`column_text`/`step` results while exercising production row mapping, transaction
handling and actor APIs; they do not claim genuine native OOM or rollback-I/O
injection. Native SQL NULL, ordinary rollback and SQLITE_FULL automatic rollback
fixtures continue to use real SQLite.

## Private state and storage errors

Supply a dedicated host state leaf below an existing stable, trusted parent.
Initialization creates a missing leaf with mode 0700. Before opening the lock or
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

SQLite uses `journal_mode=DELETE`, `synchronous=EXTRA` (native level 3), and
`fullfsync=ON`. EXTRA requests the directory synchronization after deleting the
rollback journal; FULL alone does not request that point, and fullfsync selects
the synchronization method rather than adding it. The regression reads native
PRAGMA values and performs a real transaction/close/reopen. It establishes the
configured durability policy and ordinary persistence, not power-loss behavior;
genuine power-loss/filesystem qualification remains unperformed. See SQLite's
[synchronous documentation](https://www.sqlite.org/pragma.html#pragma_synchronous).

`JournalStorageError` is public and exposes a stable `kind` (`alreadyOwned`,
`sqlite`, `filesystem`, `invalidDirectory`, `invalidState`), diagnostic `message`,
optional SQLite primary/extended codes and optional POSIX code. Its localized
message is useful without parsing it to classify errors. SQLite diagnostics are
captured while the handle is valid. `JournalTransactionError` is a separate
public composite carrying `originalError` and `rollbackError`; both appear in its
localized diagnostic, even when the original cause is an `AdmissionError`.
Automatic SQLite rollback preserves its original cause. `AdmissionError` has
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
journal transactions, without an actor suspension between validation and commit.

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
backup and verify that policy. This package does not set that filesystem
attribute. Restore exclusion and fresh-epoch behavior still require native
qualification; backup restoration cannot be treated as already safe.

Pre-production host gates also include local controller replacement/revocation
that blocks admission, invalidates authority and cancels owned work; explicit
per-run controller ownership; and schema version/migration planning. This package
has a persistent single-controller binding, not an enrollment/revocation API or
a schema migration. Deleting the database is not a controller replacement
procedure. Its synchronous SQLite work also needs dedicated-executor performance
qualification before host integration; no dedicated executor is implemented here.

Native TLS and authenticated transport, Tailscale integration, enrollment/key
management, process supervision, UI and notifications remain later gate 1 work.
The package and its automated tests do not establish native or physical-device
qualification. Gate 2 production extraction remains pending that qualification.
