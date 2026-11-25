# MAYUNDO — Attack-Chain Architecture & Blue-Team Detection Map

**Reconstructed from observed behaviour** (SHA-256 `3f3e84744c41d44ce8ec2cbbb6e97b837b5ea9e18cadee57781497ad23d80e09`, Hybrid Analysis / ANY.RUN).
This is **defensive reference material only** — it describes how the malware operates and how to detect it; it does **not** reproduce any operational malware code or a re-infectable artefact.

---

## 1. Overview

MAYUNDO is a **USB worm + spyware/RAT hybrid**. It propagates by copying itself onto every mass-storage device it touches, hides the real contents, and lures a victim into clicking a decoy that looks like `USB-explorer.exe`. Once executed, it installs persistence, phones home over an encrypted C2 channel, harvests credentials/browser data/system info, and keeps a single-instance mutex so it cannot be easily respawned. It also carries anti-analysis features (anti-VM, anti-debug, XOR obfuscation, PE forgery) so detection and reverse-engineering are worked hard.

---

## 2. One-shot attack chain (text diagram)

```
[attacker] ──USB dropper──> [victim's machine]
                              │
                              ▼
              ┌──────────────────────────────────┐
              │  victim plugs in a USB drive      │
              │  (hidden real contents shown)      │
              └──────────────┬───────────────────┘
                             ▼
              ┌───────────────────────────────┐
              │  autorun.inf / USB-explorer.exe│
              │  (disguised entry point)      │
              └──────────────┬────────────────┘
                             ▼
              ┌───────────────────────────────┐
              │  payload runs as hidden       │
              │  USB-explorer.exe window      │
              └──────────────┬────────────────┘
                             ▼
        ┌───────────────────────────────┐
        │  LOCAL PHASE                 │
        │  • enumerates drives          │
        │  • copies to every USB port   │
        │  • writes registry Run entries│
        │  • single-instance mutex      │
        └──────────────┬────────────────┘
                             ▼
        ┌───────────────────────────────┐
        │  C2 / SPY PHASE               │
        │  • outbound encrypted beacon    │
        │    (ChaCha20 -> AES -> RC4)     │
        │  • harvest credentials/API    │
        │  • emails, system info,       │
        │    installed software         │
        │  • SQL queries (browser data) │
        │  • bot-communication commands │
        └───────────────────────────────┘
                             ▼
        ┌───────────────────────────────┐
        │  EFFECTS                     │
        │  • credential theft           │
        │  • browser data exposure      │
        │  • info loss                  │
        │  • further infection of USB   │
        └───────────────────────────────┘
```

---

## 3. Component breakdown

### 3.1 Spread — USB worm
- Enumerates logical drives (all mounted storage including network shares where possible).
- For each writeable/friendly target it writes `USB-explorer.exe` + `autorun.inf`.
- Hides the original (legitimate) USB contents, so `USB-explorer.exe` looks like the only file in the drive root.
- `USB-explorer.exe` is a decoy: clicking it opens the device contents in another window, while the real payload lands in memory and persists.
- `autorun.inf` drives the decoy's auto-execution on many Windows setups (and its removal is currently required).

### 3.2 Persistence
- Uses `reg.exe` / `REGEDIT.EXE` to manipulate `Run`/auto-start registry keys — legit binaries doing the work to hide in plain sight.
- Writes a PE file header to disk (a marker / payload stub).
- Starts `cmd.exe` with AutoRun disabled — keeps a local foothold while suppressing the normal autorun chain.
- Checks supported UI/locales and may skip execution on certain locales (localisation guard).

### 3.3 C2 / spyware
- **Outbound encryption**: ChaCha20 → AES → RC4 layering, so captured traffic looks like random noise even if intercepted.
- **Credential harvesting**: harvests credentials through API calls intended for credential theft.
- **Data collection**: emails, system info, installed software.
- **SQL queries**: targets a data store — almost certainly browser data (passwords/cookies/Sessions).
- **Bot commands**: returns command-oriented plumbing so the operator can direct the host.

### 3.4 Evasion / anti-analysis
- **PyInstaller packing** — the real payload is hidden inside a packed archive.
- **High entropy** — encrypted/compressed content; static hash matching fails.
- **XOR loops** — decodes the payload only at runtime; static unpacking is defeated.
- **Anti-VM** — detects virtualised / analysis environments and changes behaviour (or sits quiet) there.
- **Anti-debug** — checks for a debugger and registers an exception handler to break/entrap analysis.
- **DLL hijacking / code injection** — loads modules into other processes to inherit trust and visibility.
- **LOLBins** — uses `reg.exe`, `cmd.exe`, `REGEDIT.EXE`, etc. for persistence and evasion.
- **PE forgery** — CRC mismatch in the PE header, suspicious imports, timestamp set very old or in the future.
- **Mutex / mutants** — single-instance guard (prevents multi-insertion).
- **Delayed execution** — waits before activating, slipping past periodic scans.

### 3.5 Other capabilities
- Loads modules at runtime (Bcrypt, RPC) to avoid shipping them statically.
- Creates directories, writes files to temp space.
- Finds well-known (likely pre-shared) C2 domains.
- Opens ports and creates named pipes.
- Delayed execution as described above.

---

## 4. Data flow (one-shot)

```
[USB]
   │  autorun.inf / USB-explorer.exe
   ▼
[payload runs]
   │  scans drives, drops copies, hides originals
   ▼
[registry Run entry + cmd.exe stub + single-instance mutex]
   ▼
[encrypted outbound beacon: ChaCha20->AES->RC4]
   ▼
[harvest: credentials, emails, system info, installed software, browser data via SQL]
   ▼
[C2 returns bot commands → repeat]
   ▼
[USB reinfection loop: every plugged-in drive gets USB-explorer.exe + autorun.inf]
```

---

## 5. Detection & response

### 5.1 Signals by phase

| Phase | Observation |
|---|---|
| **USB spread** | `USB-explorer.exe`, `autorun.inf` appear on drives; hidden folders; `Run` key entries; new `.exe` on removable storage |
| **Persistence** | `cmd.exe` AutoRun disabled; registry Run entries pointing at unusual paths; `reg.exe` from unexpected processes |
| **C2 / spyware** | Encrypted outbound traffic (high-entropy, multiple cipher layers); outbound SQL; outbound credential/API calls; long-lived named pipes |
| **Evasion** | Suspicious PE/CRC/timestamp; high-entropy packed file; signature-hit processes in a VM; debugger locks |

### 5.2 Detection rules (conceptual, not operational code)

**Manifest** (should be present on a host with the worm): `USB-explorer.exe`, `autorun.inf`, hidden `Explorer` folder, `cmd.exe` AutoRun disabled, registry `Run` entries pointing at unusual paths, mutex for the single-instance guard, temp files created with delayed activation, outbound traffic to a known/lookalike C2 domain using multi-layer encryption.

**Detection pattern**: `run-key-creation AND usb-device-connected AND high-entropy-outbound AND (multi-layer-cipher OR known-C2-domains)` — where "high-entropy" means a process writing/reading data at near-random byte entropy and "multi-layer-cipher" means observation of a ChaCha20, AES and RC4 handshake in the same session.

### 5.3 Response actions
1. **Isolate the host** (network) and remove it from any jump/bridging segment.
2. **Block outbound** to the C2 domain/port(s) and any related IP.
3. **Scan for and clean**: remove GPLControl.exe, the disguised `Libraries` folder, the `DriverFix` scheduled task, and the orphaned `ProgramData` file (already done on this host).
4. **Re-scan USB drives** for `USB-explorer.exe`, `autorun.inf`, hidden `Explorer` folders — delete all three.
5. **Full Windows Defender scan** on the host.
6. **Rotate credentials** — the RAT may have harvested them.
7. **Check browser extensions** for anything suspicious.
8. **Verify USB drives stop re-infecting** — confirm no new `autorun.inf`/decoy `.exe` after cleanup.

---

## 6. Detection rule reference (for a hunting run)

| Phase | Signal | Suggested check |
|---|---|---|
| Spread | new `USB-explorer.exe` / `autorun.inf` on removable media | `file_event` on removable-class drives |
| Persistence | `reg.exe` / `REGEDIT` → Run-key write, `cmd.exe` AutoRun disabled | EDR registry-action + process-command-line |
| C2 | outbound TCP to C2 domain, multi-layer encryption | network capture → entropy / cipher-layer analysis |
| Evasion | PE CRC/timestamp anomaly, XOR-loop, anti-VM flags | scan signature / behavioural anomaly |

---

## 7. Actions still required (from the cleanup report)

1. Plug in a USB drive → scan for `USB-explorer.exe`, `autorun.inf`, hidden `Explorer` folders → delete all three.
2. Full Windows Defender scan on the host.
3. Change passwords — the RAT may have harvested them.
4. Check browser extensions for anything suspicious.
5. Verify USB drives stop re-infecting after cleanup.

---

## 8. Sources

- Hybrid Analysis: https://hybrid-analysis.com/sample/3f3e84744c41d44ce8ec2cbbb6e97b837b5ea9e18cadee57781497ad23d80e09/695b5a17bebb2c205e086f73
- ANY.RUN: https://any.run/report/3f3e84744c41d44ce8ec2cbbb6e97b837b5ea9e18cadee57781497ad23d80e09/571931b5-0d6e-4bf7-9835-890e0585b3cd
- Windows Malware Response skill (hermes)

---

*Created: 2026-11-25*
