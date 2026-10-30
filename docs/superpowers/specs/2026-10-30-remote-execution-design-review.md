# Review: OpenMinis remote execution on Mac

Date: 2026-10-30
Reviewed: [`2026-10-30-remote-execution-design.md`](2026-10-30-remote-execution-design.md) (cited below as `L###`)
Source checked at: `1a71df0`, the spec's stated baseline and the current `main` HEAD.

## Verdict

**Not ready for an implementation plan.** The safety model is careful: idempotent admission, no silent fallback, host as the enforcement point, and honest limits on sandboxing. The gaps are elsewhere:

- One stated premise is false for iOS (Tailscale, finding 1).
- One is false for credentials (sync, finding 4).
- The main use case stalls under the proposed defaults (finding 2).
- The largest piece of work has no incremental path (finding 3).

Findings 1-4 change the design or its cost, so settle them before planning. Findings 5-12 are design gaps to close in this document. Findings 13-21 can be closed here or carried into the plan as explicit requirements.

### Decisions needed from you

| Decision | Recommendation | Finding |
| --- | --- | --- |
| How does a pocketed phone learn that a Mac run needs it? | Allow a content-free CloudKit "attention" hint, and add a run-scoped approval mode | 2 |
| What is the first milestone? | Stub agent over real Tailscale and mTLS on physical devices, before touching the agent loop | 1, 3 |
| Does the Mac participate in existing iCloud sync? | No. Registry only in v1 | 4 |
| Native macOS or Mac Catalyst for the host? | Compare both explicitly; the spec never considers Catalyst | 3 |
| Does approval need Face ID? | Yes | 7 |

## Blockers

### 1. iOS has no Tailscale integration to reuse

**Spec:** L51 "reuses connectivity infrastructure already present in the repository"; L115 "Reuse the embedded tsnet approach for both builds". **Confidence:** high for this tree.

**Evidence:**

- No Swift or Objective-C file in `src/ios` calls any `MinisTs*` or `MinisNet*` function. The only Tailscale mentions are a comment at `src/ios/iSH/ISHKernel.m:1351` about guest Go programs, a comment in `src/ios/Shared/NetworkMonitor.swift`, and one test file. `Localizable.xcstrings` has no Tailscale strings.
- The only real app integration is Android (`src/android/.../network/TailscaleNode.kt`).
- The local, gitignored `Rclone.xcframework` (built Sep 25) exports only four `MinisRclone*` symbols and no `MinisTs*`. `deps/build_rclone_ios.sh` would link tsnet into a rebuilt archive, but this copy does not have it.
- `deps/build_rclone_ios.sh:44` builds `GOOS=ios` only, with device and simulator slices. There is no macOS slice.
- `deps/rclone-mobile/tsnet/tsnet.go` has no listener and no byte-stream export. The C surface is start/stop/status/routes, `DialTest`, and a SOCKS proxy.

**Impact:** The spec's table frames Tailscale as the cheaper choice because the code already exists. On iOS it is new work: login flow, node lifecycle across suspension, state directory and data protection, `SetDefaultRouteInterface` feed, status UI, and a rebuilt archive. L66 says the bridge still needs work, but understates this. The comparison against a relay at L51-52 should be redone with the real cost.

**Recommendation:**

- Correct L51, L66 and L115.
- If an iOS network module exists outside this tree, state that and make it the baseline.
- Make "iPhone on cellular reaches a Mac tsnet listener in a signed build" the first milestone. Qualification item 6 currently treats it as an end check.
- Apply the Tinfoil lesson to the Go work: launch the real signed app early and check `nm` for a single `runtime.main`. The earlier two-runtime crash passed unsigned builds and macOS harnesses, and only showed up when the signed app launched.

### 2. Per-command approval plus no wake path stalls the main use case

**Spec:** L82, L145, L137, L139, L184. **Confidence:** high.

**Failure scenario:** The user starts a Mac task and locks the phone. The agent's first `shell_execute` needs approval. The phone is suspended, so its connection and tsnet node are gone. Nothing tells the user, and the run sits until they happen to reopen the app.

**Why existing mechanisms do not cover this:**

- L139 keeps approvals off CloudKit, and the spec has no other push path.
- The Mac cannot send APNs without a provider key or a server, and our own relay is excluded (L36).
- The local `user_ask` notification (`src/ios/Agent/Chat/UserAskCenter.swift:382`) is posted by a running app that owns the loop. A suspended remote client cannot post it.
- The `remote-notification` background mode exists (`src/ios/Info.plist:242-248`), but it only helps if something sends a push.

**Also undefined:** what happens when an approval's "bounded lifetime" (L145) expires. It could return a denial to the model, which may try another route, or pause the run, or fail it. `user_ask` already has a designed answer: an explicit timeout result stating that nothing was applied (`UserAskCore.swift:387-392`).

**Recommendation:**

1. Add an "attention" channel: a CloudKit record holding only session ID, host and a timestamp, which raises a notification. It has no authority, and the phone fetches the actual request over the host protocol. L139 needs a narrow carve-out. L201 already notes that notifications coalesce, so a missed one has to be harmless.
2. Add a run-scoped or rule-scoped approval mode as a user choice. An agent loop runs dozens of commands per task, and approving each one on a phone is unusable. It also trains people to tap through, which weakens the control it is meant to provide.
3. Specify expiry behaviour. Pausing the run with the approval still pending is the safest option. Model-visible expiry should match the `user_ask` timeout wording.
4. Put "phone locked at first tool call" in the qualification list.

### 3. Agent-core extraction is the whole project and has no incremental path

**Spec:** L72, L76, L179. **Confidence:** high on the facts, medium on the Catalyst option.

**Evidence:**

- `AIChatViewModel+AgentLoop.swift:10-11` says it directly: "runAgentLoopCore is a single ~2,000-line function; splitting it further needs real refactoring, not a move."
- `AIChatViewModel` is a `@MainActor` class spread across about 27,000 lines of extensions.
- 115 of the 309 Swift files in `Agent/` and `Providers/` import UIKit, including `AnthropicAgentProvider.swift`, `ProviderConfigStore.swift` and six of the eight OAuth managers.
- The loop depends on singletons (`ProviderConfigStore.shared` appears 18 times, plus `ChatStore`, `SkillStore`, `MCPStore`, `UserAskCenter`).

**Impact:** L76 rightly forbids a replacement loop, but as a result nothing on the Mac can run until extraction is finished, while the shipped iPhone app carries all the regression risk. The spec gives this one paragraph and no sequencing. Regression evidence is also limited: `libish_emu.a` is device-only, so the app cannot build for the Simulator (`deps/build_rclone_ios.sh:8-11`). "Relevant repository checks pass" (L179) therefore means less than it sounds.

**Recommendation:**

1. Require a milestone order in this document. First, a stub agent behind the real protocol, which qualifies Tailscale, mTLS, the journal, approvals and reconnect at no risk to the iPhone app. Then behaviour-preserving seams, with characterization tests added before each move. Then the real Mac runtime.
2. Add Mac Catalyst to the approach table. A non-sandboxed Catalyst host might avoid removing UIKit from code that only needs it incidentally. Device-only and iOS-only dependencies would still need gating. It may lose, but it could remove a large part of the extraction and should be rejected on evidence. "Designed for iPad" (`SUPPORTS_MAC_DESIGNED_FOR_IPHONE_IPAD`) is not an alternative, since I would not expect it to allow spawning native processes.
3. Say how Mac and iOS stay in parity afterwards, since retry, fallback and compaction behaviour changes often.

### 4. The "opt-in" credential sync premise is false, and the Mac's role in sync is undefined

**Spec:** L37, L139, L151, L153. **Confidence:** high on the facts. The cross-app Keychain outcome depends on the bundle ID and access group chosen.

**Evidence:**

- L151 calls existing credential sync "explicit" and "opt-in". `UploadPolicy.isEnabled` defaults every category to on (`src/ios/Agent/Sync/V2/UploadPolicy.swift:90-94`).
- `ProviderConfigStore.saveAPIKey` always writes with `kSecAttrSynchronizable = true` (`src/ios/Providers/ProviderConfigStore.swift:3628-3631`).
- `SyncedProviderInstanceV3` carries `secretBlob` (`SyncedTypes.swift:398`). Env var secrets, memory, soul and skills also sync.

**Failure scenarios, if the Mac reuses this code:**

- Phone API keys, env secrets and memory reach the Mac automatically, which breaks L37 and L151 with no code written to do so.
- Mac `SessionV2` records reach the phone with `remoteDeviceId` set. `ContentView+RemoteSessions.swift` then lists them as read-only sessions under an `iphone` icon, so a hosted chat appears twice.
- That same list offers **Fork Session** (`ContentView+RemoteSessions.swift:60`, `AIChatView+Banners.swift:245`). This creates a runnable local copy carrying Mac paths, and it bypasses the "explicit copy must disclose" rule at L127. It also comes close to the L39 failure condition about reusing the wrong filesystem context.

**Recommendation:**

- Decide explicitly: in v1 the Mac build does not run `SyncCore` and uses only a new, separate registry record.
- Give the Mac its own Keychain service names, with non-synchronizable items.
- Exclude host sessions from the existing session sync and fork paths.
- Correct L151.
- L139's "optional" transcript snapshots should be deferred. They are the source of most of this interaction, and L139 already admits the reconciliation is unsolved.

## High

### 5. Enrollment does not let a human authenticate the peer, and the phone's pin is unspecified

**Spec:** L103-107, L109. **Confidence:** high.

- L104 has the Mac show "that controller's identity", but nothing on screen lets the user tell their phone from an attacker's device. Names are attacker-chosen and a key fingerprint means nothing without a second display to compare against. The threat being defended against is exactly a hostile tailnet peer (L39), and it can ask for approval while calling itself "My iPhone".
- L107 lets unapproved candidates request enrollment whenever hosting is on. That allows prompt spam and exposes the parser to unauthenticated peers.
- Only the Mac's allowlist is specified. L109 protects the Mac from iCloud key replacement, but the phone's trust in the host key is not defined. `SyncDeviceV2` uses `conflictPolicy: .alwaysAccept` (`SyncedTypes.swift`, the `SyncedDevice` metadata). If the phone trusts whatever the record says, a replaced record redirects it to a fake host, which then receives attachments and can present misleading approvals.

**Recommendation:**

- Add a short authentication string, derived from the TLS exporter and shown on both devices.
- Accept enrollment only during a pairing window opened on the Mac and lasting a few minutes.
- Use a separate port or ALPN for enrollment, with minimal parsing.
- Pin the host key on the phone at enrollment, and treat any change as a new enrollment.
- Require the phone's key to match its private-database record as well as the code comparison.
- Extend qualification item 3 to cover impersonation during enrollment and a substituted host key.

### 6. An approved shell command can tamper with the host's own trust state

**Spec:** L109, L115, L147. **Confidence:** high in principle. Storage is not yet chosen.

L147 accepts that a command runs with full user permissions. It does not follow that through to the host itself. A single approved or injected command could add a controller key to the allowlist, edit the journal or approval state, copy the tsnet state directory (the node's identity), or replace the companion's config. A one-time mistake then becomes a persistent backdoor that outlives the approval.

**Recommendation:**

- Store the allowlist and its integrity key in the Keychain, with access limited to the signed app. Verify it on load.
- Keep the journal's authority fields under a MAC.
- Encrypt the tsnet state, or state plainly that node identity theft is accepted.
- Give the shell a scrubbed environment, with no inherited secrets and no path back to host control sockets.
- Add a qualification test: a shell command cannot change who is authorized.

### 7. Phone approvals have no user-presence check, and a lost phone cannot be revoked remotely

**Spec:** L96, L109, L145. **Confidence:** high.

The spec treats a phone holding the key as the user. A Keychain key used for a background mTLS handshake cannot also require biometrics. So anyone holding an unlocked phone, or a phone with the app open, can approve arbitrary commands on the Mac. Revocation is local to the Mac (L109), so a phone lost while travelling stays authorized until the user is physically back home.

**Recommendation:**

- Use a second approval key gated by `.userPresence`. Approvals are signed with it, and the host verifies the signature independently of the channel. This also strengthens "the host remains the enforcement point".
- Offer an emergency path, for example a signed "revoke controller" from another enrolled device.
- Otherwise document that a lost phone means using Tailscale's admin console to remove the node as the remote kill switch.

### 8. "The same agent" has no defined feature surface

**Spec:** L72-76, L119, L143, L153, L159. **Confidence:** high.

The spec's lists do not match the tools and UI that exist.

| Existing feature | What the spec says | Gap |
| --- | --- | --- |
| `agents` tool (sub-agents) | L159 cancels "child agent work"; L143 omits the tool | Is it on the Mac? Its description forbids delegating work that "needs the user's confirmation mid-way", so per-command approval conflicts with it |
| `user_ask` | Not mentioned | Needs its own protocol operation; L119 has none |
| MCP (`MCPStore`) and skills (`SkillStore`) | L153 "host-local"; MCP absent | Do they run? Who configures them on a small settings app? |
| `memory_*`, `read_image`, `browser_use` | L153 keeps memory host-local; L143 lists no such tools | Each needs an explicit yes or no |
| Directory listing, file transfer | L143 "dedicated tools" | Not existing model tools, so these are new behaviour |
| System prompt | Not mentioned | Hard-codes `apk add`, iSH and `/var/minis/...` (`AIChatViewModel+SystemPrompt.swift:57-114`) and needs a host-aware version |
| Edit, retry, delete-from, rerun tool block | Not in L119 | `AIChatViewModel+EditMessage.swift`, `+Rerun.swift` |
| Session list, delete, rename | Not in L119 | L119 has create/load only |
| Compaction, title generation, thinking level, model switch, slash commands, prompt queue | Not mentioned | Runs where, and how does the phone trigger it? |

**Recommendation:** Add a capability matrix to this spec listing each tool and UI action with one of: on host, via protocol, or disabled with a stated reason. Otherwise this table gets decided piecemeal during implementation.

### 9. The phone's storage for remote sessions is not specified

**Spec:** L82, L125, L139. **Confidence:** high.

The sidebar, search and message list read from `ChatStore`, and `AIChatViewModel` loads and writes through it. The spec says the Mac owns canonical state and the phone owns drafts and preferences, but not where a Mac chat lives on the phone. That leaves these open:

- What does the chat list show with the Mac asleep, and does a remote chat show history offline? L139 relies on an optional sync feature for this, which finding 4 recommends removing.
- If a local mirror is used, its writes must not reach `sync_dirty_records`, or the phone re-uploads Mac state through the last-write-wins path L139 warns about.
- Does search cover remote chats? Do they count in usage stats and backup? `ChatStore+BackupRestore` would otherwise restore mirrors as if they were local.
- The existing `remoteDeviceId` gate (`AIChatViewModel+Send.swift:37`) means "read-only". A hosted session must not reuse this field (L125 covers this), so every one of those call sites needs a separate host-aware decision.

**Recommendation:** Specify a non-synced local mirror as a cache with the host as authority, and define its offline read behaviour, including exclusion from sync and backup.

### 10. `minis://` links and file references resolve in the wrong filesystem

**Spec:** L39, L143, L153. **Confidence:** medium-high. I read the prompt and the listed callers but did not trace the renderer end to end.

The system prompt tells the model to emit `![desc](minis://attachments/filename)` and `[name](minis://workspace/filename)` (`AIChatViewModel+SystemPrompt.swift:107-108`). The scheme is handled by phone-side code (`MinisURLPathDecoding.swift`, `ChatURLBrokerage.swift`, `RawMessage+Conversion.swift`). In a Mac session, that link would show nothing, or a phone file with the same name, which is the "wrong filesystem context" failure named at L39 but for display rather than execution. The same applies to the `@` mention index (`FileMentionIndex.swift`), offloaded tool output in `/var/minis/offloads/`, and attachment rows.

**Recommendation:** Use a host-scoped resource URI, fetched through the protocol. A remote session must never resolve against local paths, and this needs a test. The `@` mention menu must query the host or be disabled.

### 11. macOS realities the spec does not address

**Spec:** L88, L143, L147, L163. **Confidence:** medium. These come from platform knowledge and nothing was tested.

- **App Sandbox:** user-level shell access requires a non-sandboxed app, since children inherit the sandbox. That rules out the Mac App Store and is a design-level consequence, not a builder choice at L90.
- **TCC prompts:** `ls ~/Documents` from a child process can raise a permission dialog on the Mac's screen while the user is away. L147 excludes Full Disk Access requests but says nothing about these. The command then hangs. Treat this as a defined state with a clear error.
- **App Nap:** L88 allows closing the settings window, and a windowless app can be throttled. Hold a `ProcessInfo` activity while hosting.
- **Idle sleep:** with default energy settings the Mac can sleep mid-run. Hold an idle-sleep assertion during active runs and show this in the UI. This does not conflict with the no-wake rule at L163. A closed lid still sleeps the Mac, so say so to the user.
- **Command limits:** the spec bounds protocol sizes (L119) but not commands. iOS has `defaultCommandTimeout = 900` and output offloading. Specify timeout, output cap and `stdin` from `/dev/null`, so that `sudo` and `ssh` prompts fail rather than hang.
- **Process groups:** L159 relies on them, so the plan needs an explicit `posix_spawn` with `POSIX_SPAWN_SETPGROUP` or equivalent, rather than assuming `Foundation.Process` provides one. Confirm that signal handling works alongside the Go runtime in the same process.

### 12. Approvals interact badly with concurrent tools

**Spec:** L129, L145. **Confidence:** high.

The loop dispatches up to `maxConcurrentTools` calls in parallel and must return results in `tool_use` order (`AIChatViewModel+ConcurrentTools.swift:5-9`, `+AgentLoop.swift:2043`). The spec does not define:

- whether parallel calls are approved individually or as a batch;
- what happens to calls already running when a sibling is denied;
- whether a denial stops the turn or returns a tool error the model can route around;
- how approvals display in a queue on a phone screen.

Also, retry and rerun could replay a tool call, so state that a rerun always needs a fresh approval (L135 implies this). Add these to the approval policy, along with "approval denied" as a defined tool result.

## Medium

### 13. The TLS and bridge boundary is not a free builder choice

**Spec:** L96, L107, L117, L190. **Confidence:** high on the constraint.

If Go terminates TLS, the private key has to cross into Go, which conflicts with L96's Keychain-only rule unless a signer bridge is built. If Swift terminates TLS with Network.framework, as seems natural, bytes need a path from `tsnet.Listen` into `NWListener`. In practice that is a loopback forwarder on the Mac and SOCKS (`tsnet.go:459`) or a similar forwarder on the phone.

That is safe under L117 only because TLS stays end to end. But any local process can then reach the enrollment path, including the agent's own shell commands. Finding 5's pairing window helps here. Choose the design now, since it affects the security review. Note also that `srv` is a package-level singleton (`tsnet.go:39`), so one process has one node. Any future general Tailscale feature on iOS would share this node, including its `Stop()` and `Logout()`.

### 14. Multi-controller, revocation and queue semantics conflict

**Spec:** L86, L109, L129, L145. **Confidence:** high.

- L109 cancels the revoked controller's "active managed runs" and denies "its pending approvals", while L129 and L145 make sessions and approvals shared across controllers. Approvals have no owner to match against. Revoking one device can also kill a run another device is watching.
- L86 lists approval requests in the Mac app, while L145 says any approved controller decides. Can the person at the Mac approve commands? Is the Mac able to stop a run with no phone connected?
- L129 queues additional turns. Does Stop cancel queued turns or only the active one? Does the existing prompt queue (`AIChatViewModel+PromptQueue.swift`) map onto this?

### 15. Journal and `ChatStore` risk being two sources of truth, and dedupe retention has a gap

**Spec:** L131-135, L190. **Confidence:** medium-high.

- The host journal is authoritative (L133), and the reused core persists to `ChatStore`. Say which one wins after a crash between the two writes, or make them one transaction in one database.
- "Returns the same result for a repeated ID" (L131) depends on retention, which L190 leaves to the plan. Compacting a request ID before the client stops retrying re-executes it, which is a named failure at L39. Require that admission records outlive the event data and are kept for the session's lifetime.
- Token deltas should not be durable one at a time. State the coalescing rule, and say whether replay is by delta or by snapshot.
- L135 covers tools. Also cover a crash during a model request, including whether partial text is kept and whether the turn is billed again on rerun.

### 16. The "small" Mac app and provider scope are underestimated

**Spec:** L76, L86, L151, L153. **Confidence:** medium-high.

L151 requires configuring credentials locally on the Mac. The repository has OAuth flows for Claude, Codex, Gemini, Antigravity, xAI, OpenRouter, Copilot and Kimi, a 4,068-line `ProviderConfigStore`, plus model groups and routing. That is a large settings surface for an app described as small, and all of it currently depends on iOS code.

L153 says "not... an added provider fallback", but L76 says to preserve behaviour and `AIChatViewModel+Fallback.swift` already implements group-level fallback. State whether an existing model group keeps its fallback on the Mac; I assume yes. Recommend limiting v1 to API-key providers, which L190 already allows.

### 17. Tailscale operations are missing

**Spec:** L102, L111, L185. **Confidence:** medium. These are from Tailscale knowledge and were not probed.

- Node key expiry means a Mac host can drop off while the user is travelling, and re-login needs its local browser. Show the expiry, warn ahead of it, and document disabling expiry for the node.
- Add explicit states for the phone and Mac being on different tailnets, and for an ACL blocking the service port. L185 lists neither, and they would look like an unreachable Mac.
- `ts_omit_portmapper` exists to avoid an iOS Local Network prompt (`deps/build_rclone_ios.sh:21-23`). Copying the tag to the Mac slice gives up some direct connectivity on the host side, so decide this deliberately. Keep `ts_omit_logtail` on Mac: without it, `tsnet.Start` calls `os.Setenv` (`tsnet.go:148`), and the comment there records a launch crash from that call path when it ran earlier in startup.

### 18. Custom signing touches more than the container

**Spec:** L98. **Confidence:** medium-high.

`iCloud.com.openminis.app` is hard-coded (`ICloudSharedZoneTransport.swift:30`), and the code also calls `CKContainer.default()` at line 2065. Keychain service names and the app group are also fixed. `Minis.entitlements` requires HealthKit, HomeKit, NFC and WeatherKit, which a custom signing identity must provision or remove. "Same CloudKit environment" also needs thought: Developer ID and TestFlight builds use Production, so new record types must be deployed to Production first. Add these to the plan's setup section.

### 19. Qualification gaps

**Spec:** L177-186. **Confidence:** high.

Add these checks:

- Launch the real signed iOS and Mac apps, and confirm a single Go runtime.
- First tool call with the phone locked (finding 2).
- Enrollment impersonation and host-key substitution (finding 5).
- A shell command attempting to change the allowlist (finding 6).
- A `minis://` link in a Mac session (finding 10).
- A TCC prompt, and idle sleep during a run (finding 11).
- A denied call among parallel tools (finding 12).
- Hosted sessions absent from the sync and fork paths (finding 4).

## Low

### 20. Do not base `executionHostID` on `DeviceIdentity`

**Spec:** L96, L125, L137. **Confidence:** high.

`DeviceIdentity` re-mints its ID when the Keychain item is absent, and then deletes the old `SyncDeviceV2` record (`DeviceIdentity.swift:96-112`, `SyncV2Bootstrap.swift:266-272`). L96 already says UUIDs are not authority. Also state that `executionHostID` derives from the host's public key, so that a re-mint cannot silently change or orphan session ownership. Also add stale controller cleanup in the Mac app for reinstalled phones.

### 21. Prefer a new record type over extending `SyncDeviceV2`

**Spec:** L94. **Confidence:** medium-high.

"Extend registration" means altering a record with `.alwaysAccept` conflict policy, `.global` scope, an existing per-launch rewrite, and older peers that do not know the new fields. A separate `ExecutionHostV1` record keeps the security-relevant fields out of general sync, and it lets the Mac stay out of `SyncCore` (finding 4).

## Checked and correct

These source claims in L59-66 match the code:

- `AIChatViewModel` combines these concerns, and the agent loop imports UIKit.
- The Xcode project is an iOS project with Designed for iPad support.
- `DeviceIdentity` is a Keychain UUID.
- `SyncDeviceV2` self-registers, and iCloud uses the private database.
- `LANTransport` is a skeleton.
- `tsnet.go` has dial and SOCKS but no listener.
- L125's reading of `remoteDeviceId` is right: `ChatStoreModels.swift:59` and `AIChatViewModel+Send.swift:37` confirm it means "from another device, read-only".

One apparent problem turned out to be fine. A comment at `ChatStoreSyncHydrators.swift:13` says `SyncDeviceV2` inbound is not wired, but it is stale: line 918 calls `upsertSyncDevice`, so phone discovery has a working read path.

## Limits of this review

This was a source read only. I built nothing, ran no tests and made no network or device probes. Go is not installed on this machine, so I did not compile the Go code or inspect the upstream `tsnet` module, and the spec's claim that it supports a listener is taken from my knowledge of upstream. I did not open the external links. Claims about macOS, CloudKit environments and Tailscale key expiry come from platform knowledge and are marked as such above. The iOS Tailscale finding covers this checkout only.
