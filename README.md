# DEATHCon 2026 - AV Evasion Workshop

Most defenders have never seen what it actually looks like when an attacker bypasses Defender, kills AMSI, or executes shellcode in memory. This workshop puts you on both sides: run the attacks, review the logs, and build detections for each technique. Hands-on labs, real payloads, real telemetry.

**Workshop Leader Location:** Seattle, WA USA

---

## Overview

Modern penetration tests increasingly fail at the same point: payload execution. Even basic endpoint protection platforms routinely block common tools, scripts, and frameworks before operators can establish access or validate controls. Understanding how antivirus engines detect malicious activity and how attackers realistically bypass those controls is now a core red team skill.

This workshop covers the full detection pipeline from both directions. On the offensive side, you will analyze what triggers Windows Defender at the static, behavioral, and in-memory levels, then apply targeted modifications to remove each detection surface without touching the payload logic. On the defensive side, you will review the telemetry each technique generates, understand what artifacts survive in event logs and EDR data, and write detections that catch the same behavior you just executed.

Rather than relying on one-click tools or prebuilt frameworks, the workshop focuses on tradecraft fundamentals: understanding detection pipelines, modifying execution paths, safely testing evasion techniques, and building repeatable workflows that translate directly to real-world assessments.

Participants work through guided labs using isolated virtual machines with real payloads: observing detection behavior, applying evasion techniques, validating successful execution, and then pivoting to the defender role to build coverage for each stage.

### Who This Is For

Threat Hunters, Detection Engineers, Security Operations Center Analysts, Dragons, Wizards, Beginner

All exercises are conducted in isolated lab environments using non-production systems.

---

## Links & Resources

All workshop links (VM downloads, lab artifacts, and reference material) are pinned in the **#🤺🛡️breaking-through-defenses-understanding-and-detecting-windows-endpoint-security-bypasses** channel on Discord.

---

## Lab Environment

### Virtual Machines

VM download links and passwords are in Discord.

#### Windows 11 Pro

```
hostname: evasion_win11
user:     eva / 3v4sion
admin:    evadmin / root3v4sion

Password hint answer: evasion
```

#### Kali Linux

```
hostname: kali-evasion
user:     kali / kali
```

---

## Labs

| # | Lab | Technique |
|---|---|---|
| 1 | `lab1-threatcheck.md` | Static analysis with ThreatCheck - identify what signatures trigger |
| 2 | `lab2-amsi.md` | AMSI bypass - kill the scan buffer before it sees your payload |
| 3 | `lab3-shellcode-loader.md` | Build a shellcode loader in C - allocate, copy, execute |
| 4 | `lab4-donut-shellcode.md` | Generate shellcode from a PE with Donut |
| 5 | `lab5-donut-sam-dump.md` | SAM credential dump via Donut shellcode without behavioral detection |
| 5 | `lab5-donut-lsass-dump.md` | LSASS credential dump via Donut shellcode without behavioral detection |
| 6 | `lab6-elastic-detection.md` | Review Elastic telemetry and build detections for the techniques above |
| 7 | `lab7-bonus-byo-shellcode.md` | Bonus: write your own position-independent shellcode |
| 8 | `lab8-bonus-byo-shellcode-loader.md` | Bonus: write your own shellcode loader |
