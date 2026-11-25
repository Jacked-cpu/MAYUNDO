# MAYUNDO Malware — Full Report & Cleanup Summary

**Classification:** Spyware / RAT / USB worm
**Sample:** `GPLControl.exe`
**SHA-256:** `3f3e84744c41d44ce8ec2cbbb6e97b837b5ea9e18cadee57781497ad23d80e09`
**SHA-1:** `3903b48194380b87e6cac0ae96d4c95cfee7440`
**MD5:** `41fe839aa45fe4b424451f38f0eb9167`
**Size:** 7.2 MiB (7,546,516 bytes)
**Type:** PE32+ executable, 64-bit, packed (PyInstaller)
**Threat Score:** 80/100 MALICIOUS (Hybrid Analysis)
**First Seen:** 2026-03-20

---

## 1. Executive Summary

MAYUNDO (discovered as `GPLControl.exe`) is a Windows malware family that combines **USB-worm propagation**, **credential/spyware harvesting**, and **RAT-like remote control** in a single PyInstaller-packed binary. It spreads by copy-pasting itself onto every USB mass-storage device it is connected to and disguising that copy as a friendly "explorer" program, which lures victims into clicking it. Once executed, it establishes persistence, phones home to an encrypted C2 channel, and harvests credentials and system information.

It was found on this host at `C:\Users\Public\Libraries\GPLControl.exe`, together with a disguised `Libraries` folder, a `DriverFix` scheduled task, and an orphaned `ProgramData` file. All have been removed and the host cleaned. Cleanup of USB media that was already exposed is still required.

> **Important:** A previously gray-area tool (Honeygain) was left on the host per your explicit request and is **not** part of this malware family.

---

## 2. Timeline History

The dates below are the timeline of the **infection** as recovered from the machine and vendor telemetry. Where the report can state a fact outright it is marked `[fact]`; where the ordering is a reconstruction from observed artifacts it is marked `[inferred]`.

| # | Date | Stage | Evidence |
|---|------|-------|----------|
| [fact] | 2026-03-20 | First seen on C2 | Hybrid Analysis / ANY.RUN telemetry (SHA-256 `3f3e…0e09`) |
| [inferred] | prior to 2026-03-20 | Initial infection (USB) | USB worm propagates by copying itself to connected storage; device reached this host |
| [fact] | post-infection | Persistence installed | `reg.exe`/`REGEDIT` Run entries, `cmd.exe` with AutoRun disabled |
| [fact] | post-infection | Command & control established | Encrypted outbound traffic (ChaCha20 / AES / RC4); SQL queries to harvest browser data; bot-communication commands |
| [inferred] | 2026-03-20+ | Credential harvesting | Harvested emails, system info, installed software; SQL queries targeting browser data |
| 2026-10-06 | cleanup | Host sanitized | GPLControl.exe, Libraries folder, DriverFix task, orphaned ProgramData file removed |
| 2026-10-06 | still open | USB media reinfection risk | USB-explorer.exe / autorun.inf / hidden Explorer folders may exist on any plugged-in drive |

**Timeline narrative.** The sample was first observed phoning home to its C2 on 2026-03-20. From there it presumably reached this host via a USB-mediated wipe (the worm's signature spread vector). Once on the host it installed persistence under `C:\Users\Public\Libraries\` — a non-standard, disguised location — then began logging and phoning home with credential and browser-data payloads.

---

## 3. What It Does

### 3.1 USB-Worm Spread (`[fact]`)
- Enumerates all logical drives on the system.
- Copies `USB-explorer.exe` + `autorun.inf` onto **every** USB / storage device plugged in.
- Hides the original USB content and shows `USB-explorer.exe` as the only entry point.
- Hiding the true contents and presenting a single explorer-style file is a social-engineering hook: the victim clicks `USB-explorer.exe` to view "their" files, which instead executes the payload in another window.

### 3.2 Persistence (`[fact]`)
- Modifies autorun registry values through `reg.exe`.
- Writes a PE file header to disk.
- Uses `REG`/`REGEDIT.EXE` to modify / delete registry entries.
- Starts `cmd.exe` with AutoRun commands disabled (an anti-analysis tat). This prevents the payload from being trivially re-run via the normal autorun chain while still leaving footholds in the registry.

### 3.3 Command & Control / Spyware (`[fact]`)
- Sends encrypted data to C2 using **ChaCha20 + AES + RC4** (multi-layer obfuscation).
- Harvests credentials through API calls (credential theft).
- Collects emails, system info, and installed software.
- Runs SQL queries against a data store (likely harvesting browser data).
- Sends bot-communication commands back to the operator.

### 3.4 Evasion / Anti-Analysis (`[fact]`)
- PyInstaller-packed binary.
- High entropy — content is encrypted/compressed.
- XOR operation loops.
- Anti-VM: identifies virtualized environments.
- Anti-debug: checks for a debugger and registers an exception handler.
- DLL hijacking / code injection into other processes.
- Uses Windows LOLBins (legitimate binaries such as `reg.exe`, `cmd.exe`, `REGEDIT.EXE`) to perform destructive/evasive actions instead of raw Win32 APIs.
- CRC mismatch in the PE header; suspicious imports; PE timestamp very old or in the future.

### 3.5 Other Capabilities (`[fact]`)
- Creates mutants (a mutex ensures a single instance).
- Loads modules at runtime (`Bcrypt`, `RPC`).
- Creates directories, writes files to temp.
- Finds well-known domains used as C2 endpoints.
- Opens ports and creates named pipes.
- Delayed execution (runs stealthily after a delay).

---

## 4. Who It Affects

- **Anyone whose system accepts untrusted USB media.** The worm's spread model is every-mass-storage-device, so the exposure is not scoped to a single user or machine.
- **Shared / kiosk / enterprise and education endpoints** that accept USB drives from others are at highest risk, because one compromised drive re-infects every host it touches.
- **Multi-language / multi-locale Windows installs** — the sample checks supported languages and *may skip* certain locales, so behavior is not uniform across every install; this makes it harder to detect with language-gated rules.
- **Users of credential-stuffed / browser-autofill workflows** — the harvesting of credentials, emails, and browser data maps directly to password-reuse and autofill attack surfaces.

This host's cleanup specifically targeted `C:\Users\Public\Libraries\`, which is why the reinfection vector was active even after the main binary was removed.

---

## 5. Why Windows Defender (and most AV) Can't See It

MAYUNDO is deliberately engineered to defeat signature- and heuristics-based detection. The techniques are:

| Technique | How it defeats detection | Observed impact |
|-----------|--------------------------|-----------------|
| **PyInstaller packing** | The real payload is hidden inside a packed archive; AV sees an inert launcher, not the code. | Static signatures don't match. |
| **High entropy / encrypted + compressed** | Packing + XOR + compression makes the binary look random, so hash/content matching fails. | `"High entropy"` flagged in the report. |
| **XOR operation loops** | XOR-decoding at runtime reveals the payload only after execution; static scanners see garbage. | Evades static_unpack heuristics. |
| **Anti-VM** | Detects virtualized / analysis environments and withholds malicious behavior (or alters behavior) to fool sandboxes. | Sandbox "clean" reports are common. |
| **Anti-debug / exception handler** | Detects debuggers and registers an exception handler to break or confuse dynamic analysis. | Dynamic traces mislead analysts. |
| **PE header CRC mismatch / suspicious imports** | Modifies the PE header CRC and uses suspicious imports so headers and import tables look "normal-but-wrong" to parsers. | Signature scanners that trust PE headers get confused. |
| **Fabricated timestamps** | PE timestamp set very old or in the future; undermines "dated" heuristics. | False-negative on build-date heuristics. |
| **LOLBins (legitimate binaries)** | Uses `reg.exe`, `cmd.exe`, `REGEDIT.EXE` — all trusted — for persistence and evasion. | Behavior looks like normal admin; no rogue binary name. |
| **DLL hijacking / code injection** | Loaded into / inside other processes so it inherits the victim process's trust and visibility. | Blends into the host, escaping process-level whitelisting. |

**Net effect:** no single static or dynamic signal is decisive, so signature-based AV (including Windows Defender) misses it until the payload is already executing and phoning home.

---

## 6. Its Tricks (TTP Summary)

- **Social engineering via USB:** hide real files, present `USB-explorer.exe`, click it and a *second* window opens "device contents" while the payload runs.
- **AutoRun zombification:** disable AutoRun then set registry Run keys, so the system won't re-prompt for the drive but will still launch hidden payloads.
- **Multi-layer C2 encryption:** ChaCha20 + AES + RC4 in sequence, so traffic looks like random noise even when decrypted.
- **Browser-data harvesting via SQL:** SQL queries toward a data store — consistent with harvesting saved browser passwords/cookies.
- **Language skipping:** check supported locales and skip execution on certain ones, avoiding the highest-friction analysis environments.
- **Single-instance mutex + delayed execution:** survives a respawn attempt and delays activation to slip past hourly scans.
- **Deferred execution via `cmd.exe` with AutoRun disabled:** runs without triggering the normal autorun path.

---

## 7. Impact / Risk

- **Credential theft** — passwords and API credentials harvested for reuse attacks.
- **Email / mailbox access** — emails collected as a secondary exfiltration target.
- **System fingerprinting** — emails, system info, installed software.
- **Browser data exposure** — likely SQL-targeted harvesting of saved credentials/cookies.
- **Bot / C2 control** — operator can direct bot-communication commands from the C2.
- **Re-infection of shared USB media** — the primary ongoing risk for the home/office.

---

## 8. Cleanup Summary (as recovered on this host)

**Removed / verified clean:**
- ✅ `GPLControl.exe` at `C:\Users\Public\Libraries\` — gone
- ✅ Disguised `Libraries` folder — gone
- ✅ `DriverFix` scheduled task (`\DriverFix` → `DriverFix.exe -auto`) — gone
- ✅ Orphaned `ProgramData\EGIJKEHCAKFCAKFHDAAAAECFCG` — gone
- ✅ No MAYUNDO files / processes / registry Run entries / scheduled tasks / services / startup entries on host
- ✅ No `autorun.inf` or `USB-explorer.exe` on host

**Left untouched (per your request):** Honeygain (gray-area PUP) — see note in §1.

---

## 9. Still Needed

1. Plug in a USB drive and scan for `USB-explorer.exe`, `autorun.inf`, and hidden `Explorer` folders → delete all three.
2. Run a full Windows Defender scan on the host.
3. Change passwords — the RAT may have harvested credentials.
4. Check browser extensions for anything suspicious.
5. Verify USB drives stop getting reinfected after cleanup.

---

## 10. USB Cleanup Instructions

When a USB drive is plugged in:
1. Open Folder Options → uncheck **Hide extensions for known file types** and **Hide protected operating system files**.
2. On the USB drive, delete:
   - `USB-explorer.exe`
   - `autorun.inf`
   - Any hidden `Explorer` folder containing executables (confirm it is not the genuine Windows Explorer).
3. Show hidden files and delete any hidden items the worm created.
4. Verify with `dir /a /s` on the USB root.

---

## 11. Sources

- Hybrid Analysis: https://hybrid-analysis.com/sample/3f3e84744c41d44ce8ec2cbbb6e97b837b5ea9e18cadee57781497ad23d80e09/695b5a17bebb2c205e086f73
- ANY.RUN: https://any.run/report/3f3e84744c41d44ce8ec2cbbb6e97b837b5ea9e18cadee57781497ad23d80e09/571931b5-0d6e-4bf7-9835-890e0585b3cd
- Windows Malware Response skill (hermes)

---

*Created: October 6, 2026*
