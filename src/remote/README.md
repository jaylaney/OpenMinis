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
network peers, user databases or OS processes.

## Admission and status

Create one `AdmissionCoordinator(directory:controllerID:)` per journal directory,
with exclusive ownership for its lifetime. Initialization durably binds the
configured controller, even before any requests, and rejects a different binding
on reopen. The synchronous journal is internal to the package, confined to that
coordinator. Sharing a directory between live coordinators or processes is not a
supported host topology.

`connect(controllerID:)` returns an opaque `ConnectionLease` with no public
initializer. Replacing the connection invalidates the old lease. A rejected
foreign-controller connect leaves the valid lease intact. Submit and reconcile
validate the controller, current lease and storage epoch before synchronous
journal transactions, without an actor suspension between validation and commit.

Each request ID has one durable disposition for its storage epoch. Matching
retries return that record; changed identity, metadata or payload conflicts are
rejected. An unknown-ID `reconcile(requestID:epoch:over:)` writes `rejectedAbsent`
before returning. This tombstone refuses all later content for that ID, including
delayed sends on a replacement connection and after reopening storage. Busy
rejections also remain terminal. A reset creates a new namespace, so IDs may be
used anew only with its new epoch.

`RequestRecord` describes admission or rejection. `admitted` means the run was
admitted, and `stopRequested` means a Stop was recorded. Neither establishes that
a command started, terminated or succeeded. Stop keeps the active slot occupied.
`status()` reports the epoch, recovery requirement and unresolved active run;
`runStatus(for:)` reports run state and any settled outcome. Only explicit host
settlement releases an active slot during normal operation. Late Stop requests
for another run cannot change the current run.

Reopening unresolved work sets `recoveryRequired`: new Start admissions are
blocked, while matching run-scoped Stop remains available. The host must verify
that recovered processes are absent before calling
`confirmRecoveredProcessesAbsent()`. That call records `interruptedUnknown` for
unresolved work and invalidates previous leases. `reset()` requires no active or
recovery-blocked work, preserves controller binding, creates a fresh storage
epoch and invalidates previous leases. Old-epoch submissions, reconciliations
and settlements are refused. Lost storage likewise creates a new epoch.

## Host trust boundary and remaining qualification

An external authenticated host adapter must supply the configured controller ID,
authenticate and authorize its connection, hold exclusive journal ownership,
verify process absence, and serve the public actor methods through its chosen
transport. Controller IDs and leases here are local admission capabilities; this
core does not authenticate people, encrypt a channel or supervise processes.

`settle(runID:epoch:outcome:)`, `confirmRecoveredProcessesAbsent()` and `reset()` are
host-internal integration APIs. They must not be exposed as unauthenticated
remote operations. The host must observe actual termination before settlement;
Stop acknowledgement alone is insufficient. Capture the storage epoch when the
run is admitted and pass that captured epoch to settlement. Connection leases
may change while a run continues, so settlement does not use a lease. An old-epoch
completion is rejected inside the journal transaction before any target-run
lookup or mutation, including when a new-epoch run reuses the same run ID.
Matching same-epoch duplicate settlements remain idempotent; contradictory
outcomes are rejected.

Native TLS and authenticated transport, Tailscale integration, enrollment/key
management, process supervision, UI and notifications remain later gate 1 work.
The package and its automated tests do not establish native or physical-device
qualification. Gate 2 production extraction remains pending that qualification.
