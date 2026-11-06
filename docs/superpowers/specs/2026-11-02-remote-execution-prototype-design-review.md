# Review: authenticated-status prototype

Date: 2026-11-03
Reviewed:
- [`2026-11-02-remote-execution-prototype-design.md`](2026-11-02-remote-execution-prototype-design.md), cited below as `L###`.
- [`../plans/2026-11-02-remote-execution-prototype.md`](../plans/2026-11-02-remote-execution-prototype.md), cited below as `P###`.
- The parent design's uncommitted revision 12 edits, read for context.

Source checked at: `fcb9bb8`, the stated baseline.

## Verdict

**Ready for implementation once findings 1 and 2 are settled.**
- **Sound:** the wire format, cryptographic transcript, enrollment state transitions and clean-store opening order. The frame payload sizes add up, the stored key and fingerprint lengths match their encodings, and the stable lock uses `flock` as the design assumes.
- **Plan:** it is now executable. Every task names its failing tests, exact interfaces and commands, and a table traces each requirement to a test.
- **Remaining gaps:** findings 1 and 2 affect the signed physical run, not Gate A. Findings 3–6 are small.

### Checks against ground truth

- Parent revision 12, the 69 existing test cases, and issues #2–#6 exist and match the descriptions.
- The X509 `1.17.0` tag exists (`133a347`). Its manifest declares Swift tools 6.0 and depends on swift-crypto `3.12.3..<5.0.0` and swift-asn1. The Task 8 dependency review covers these.
- The package floors are macOS 13 and iOS 16 (`src/remote/Package.swift`).
- Production bundle IDs use `com.openminis.*`.

## Earlier review of the scripted prototype

An earlier version at this path proposed a scripted-execution prototype. Its review findings were resolved as follows.

| Earlier finding | Resolution |
| --- | --- |
| The pairing code covered only static keys and the invitation ID, so it could be brute-forced | **Fixed.** The Mac draws a nonce after the claim is fixed, and the phone shows a code only for its own accepted claim (A5, L194, L196). The parent design (revision 12, step 3) carries the same rule. |
| The 10-second health lease would cancel a quiet 900-second command | **Deferred** to gate B3, which requires an explicit periodic heartbeat (L233). |
| The 128 MiB validation-copy cap, plus 16 MiB of retained output per command, could make the store unopenable | **Removed.** The status store has no output growth (L83); budgets move to gate B4 (L234). |
| The Stop "clarification" changed the parent contract | **Parent updated.** Revision 12 no longer settles while descendants may remain, and it concedes that markers can't prove absence. |
| The plan's steps were too coarse to delegate | **Largely fixed.** There are 13 tasks with named tests, interfaces and commands (P56). |
| The validation-copy machinery was disproportionate | **Replaced** with refusing any companion file (L88). The cost is stated: a crash mid-write leaves the store unopenable (L96). |
| Bundle IDs contained a personal name | **Fixed** (L50). The issue links still contain the fork owner's GitHub handle. |
| Any tailnet peer could hold both pending connection slots | **Acknowledged** (A11, L211). The physical run must restrict the Mac port to the phone with tailnet rules. |
| A Stop could race the GO send | **Parent updated.** Revision 12 promises bounded cancellation, not "nothing starts" (B6). |

## Findings

### 1. The Mac Keychain settings need a signed app with an entitlement

Severity: medium. Confidence: fairly high.

L204 and P22 require after-first-unlock, this-device-only accessibility for private keys.
- **The problem:** on macOS that accessibility applies only to the data-protection keychain. Using it needs `kSecUseDataProtectionKeychain` and an app signed with a team and a keychain-access-group or application-identifier entitlement. For a directly distributed app, that means a provisioning profile.
- **The gap:** L50 leaves signing unset and never names the entitlement.
- **Consequence:** the first signed run could fail on Keychain access, or quietly fall back to the file-based keychain, which ignores accessibility settings.
- **Fix:** state the Keychain flag in Task 8 (P143), and list the entitlement and provisioning profile in the physical manifest (P231).

### 2. Each Mac/phone pair gets one enrollment, with no way to start over

Severity: medium. Confidence: high on the interfaces.

**Mac side**
- Revocation is permanent and never reopens the slot (L79, L81).
- Reset and re-enrollment are unavailable (L94).
- After revocation the service fence never resets (P172), so a revoked installation is unusable.

**Phone side**
- It stores one paired host (`loadPairedHost() -> PairedHostRecord?`, P139).
- It has no forget-host action (P183).
- A tentative pin can't overwrite a saved one (L196, P185).
- iOS Keychain items survive app deletion, so reinstalling the probe doesn't clear its pairing.

**A trap in the manual reset:** a fresh Mac store reuses the existing Keychain host key (L91). Deleting only the Mac's state directory gives a new host ID with the same pin. A phone still holding the old record can't pair with it.

**Why it matters:** the physical cases need several fresh pairings: enrollment race, wrong key, reconnect after revoke (P231).

**Fix:** add a manual reset procedure for both sides to the physical manifest (state directory and Keychain items), or add a debug-only forget-host action to the probe.

### 3. A single stray file blocks the store permanently

Severity: low. Confidence: moderate.

Opening step 2 refuses every entry except the lock and the database (L88). L96 asks that failed state be kept for diagnosis. Inspecting the folder in Finder can create `.DS_Store`, after which the store never opens again.

**Fix:** tolerate named Finder metadata files, or document that the state folder must not be opened in Finder.

### 4. The macOS firewall prompt is not listed

Severity: low.

With the application firewall on, a listening app triggers an "accept incoming connections?" alert, and a changed code signature can bring it back. L223 and P15 list the actions the documents don't authorize, and privacy prompts among them, but not this alert. Add it to the physical manifest's expected prompts.

### 5. Revoking before any phone has enrolled is undefined

Severity: low.

The operation table covers only `enrolled → revoked` (L79). Say whether revoking an `unenrolled` slot refuses, does nothing, or disables hosting.

### 6. The bundle-ID prefix isn't one the fork owns

Severity: low.

`org.openminis.prototype.*` (L50) is neither the upstream `com.openminis.*` namespace nor one owned by the fork. It doesn't matter for unsigned builds, but decide it before registering identifiers for the signed run.
