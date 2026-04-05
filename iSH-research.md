# iSH: Linux Shell on iOS — Research Report

> **Compiled:** April 2026 | **Sources:** [iSH GitHub](https://github.com/ish-app/ish), [iSH Wiki](https://github.com/ish-app/ish/wiki/What-works%3F), [ish.app](https://ish.app), [HackMag](https://hackmag.com/mobile/www-ish), [The Register](https://www.theregister.com/2020/11/09/apple_cracks_down_on_terminal/)

---

## TL;DR

- iSH is a free, open-source iOS app that runs a real Alpine Linux shell locally on iPhone/iPad using a usermode x86 32-bit emulator — no VM, no hypervisor, no cloud.
- It works by translating x86 Linux syscalls to iOS equivalents in real time via threaded-code gadgets, not JIT compilation (which Apple prohibits).
- Performance is 5–10x slower than native; compute-heavy tools like Python, pip, and ffmpeg transcoding are noticeably sluggish.
- Security-relevant tools — nmap, metasploit, openssh, openssl, tor, curl, git — work with caveats; raw packet capture, ifconfig/ip, and anything requiring a full `/proc` filesystem do not.
- Best used as a local CLI scratch environment or SSH launch pad; for serious security work, SSH into a remote Linux box is more practical.

---

## What Is iSH?

[iSH](https://ish.app) is a free, open-source iOS application that provides a fully local Linux shell environment on iPhone and iPad. Rather than connecting to a remote server or running a hypervisor, iSH brings the shell directly onto the device using a custom usermode x86 32-bit emulator paired with a syscall translation layer. The emulator intercepts x86 Linux syscalls and remaps them to their iOS equivalents in real time, allowing standard Linux userspace binaries to run without modification.

The userspace environment is [Alpine Linux](https://alpinelinux.org/) — a minimalist, BusyBox-based distribution — managed via the **apk** (Alpine Package Manager). This gives users access to a wide catalog of Linux software packages directly on their device.

iSH was created by **Theodore Dubois** and is maintained as an open-source project on [GitHub (github.com/ish-app/ish)](https://github.com/ish-app/ish), where it has accumulated **19,600+ stars** and **1,300+ forks** across 4,242 commits. The app is free on the App Store, has been downloaded over **631,000 times**, and holds a **4.6–4.8/5 rating**. The latest stable release is **v1.3.2 (build 494)**, published in May 2023; development has slowed since then. Beta versions are available via TestFlight.

### Codebase Composition

| Language | Share |
|---|---|
| C | 70.0% |
| Objective-C | 21.4% |
| Assembly | 5.4% |
| Swift | 0.8% |

The heavy use of C and hand-written assembly reflects the performance-critical nature of the emulator core.

---

## How the Emulator Works

iSH's architecture is unconventional, shaped entirely by iOS platform restrictions.

### Threaded Code Gadgets (Not JIT)

Apple prohibits JIT compilation on iOS for third-party apps (only Safari's JavaScript engine is granted this privilege). iSH therefore uses a **custom interpreter** built around a technique called *threaded code*, similar to how some Forth interpreters operate. Instead of compiling x86 instructions to native ARM on the fly, the interpreter generates an **array of function pointers** — each entry called a "gadget." Each gadget executes a small operation and ends with a tailcall to the next gadget in the array. This approach is approximately **3–5× faster** than a naive switch-dispatch interpreter and avoids any need for executable memory mapping.

The gadgets themselves are written mostly in assembly for maximum performance, as documented in the [iSH GitHub repository](https://github.com/ish-app/ish).

### Syscall Translation

The emulator intercepts over **200 Linux syscalls** and maps them to iOS equivalents. When a Linux binary calls, say, `read()` or `mmap()`, the translation layer converts that into the corresponding iOS system call. This is what allows real Alpine Linux binaries to run — they believe they're talking to a Linux kernel, but the translation layer mediates every interaction.

### What iOS Restrictions Force

| iOS Restriction | Impact on iSH |
|---|---|
| No JIT compilation | Cannot compile x86 → ARM at runtime; uses gadget interpreter instead |
| No `fork()` syscall | Cannot spawn child processes via fork |
| No hypervisor access | Cannot run a full VM |
| No raw sockets | Limits network tools (no tcpdump, restricted nmap) |
| No `/proc` filesystem | Partial emulation only; many `/proc` paths missing |
| App sandbox | Cannot access other apps or system files |
| No loopback TCP to other apps | Cannot connect via TCP to other local iOS apps |

In 2020, Apple's App Store review team flagged iSH for allowing user code execution and nearly removed it from the store. iSH appealed, and Apple ultimately allowed it to remain — but the incident highlighted the inherent tension between a local Linux emulator and Apple's app policies ([The Register, November 2020](https://www.theregister.com/2020/11/09/apple_cracks_down_on_terminal/)).

---

## Compatibility Reference

The following is drawn from the [official iSH wiki](https://github.com/ish-app/ish/wiki/What-works%3F).

### What Works

#### Shells & Editors

`bash`, `zsh`, `fish`, `vim`, `nvim`, `nano`, `emacs`, `vi`

#### Languages & Runtimes

| Tool | Status |
|---|---|
| Python 3 | Works — slow |
| pip | Works — very slow |
| Node.js | Works |
| Ruby / irb / gem | Works |
| Perl | Works |
| PHP 7 + 8 | Works |
| R | Works |
| gcc / clang | Works |
| gawk | Works |

#### Networking & SSH

| Tool | Status |
|---|---|
| curl (HTTPS) | Works |
| wget (HTTPS) | Works |
| openssh client | Works |
| openssh server | Works with caveats (SHA-1, not SHA-2) |
| mosh | Works |
| dropbear client | Works |
| dropbear server | Works with `-E` flag and port >1024 |
| lftp | Works |
| tor | Works — can proxy SSH and HTTP/browser clients |
| resolvconf | Works |

#### Security Tools

| Tool | Status | Notes |
|---|---|---|
| nmap | Works | Requires execution modifications |
| metasploit-framework | Works | Launch with `msfconsole -n` |
| tor | Works | Can proxy SSH + HTTP |
| snmpwalk | Works | |
| openssl | Works | Including certificate signing |
| openssh | Client works; server works | Server uses SHA-1, not SHA-2 |
| dropbear | Works | Server: `-E` flag + port >1024 |

#### Dev & Utility Tools

`git`, `gcc`, `clang`, `make`, `gdb` (Alpine 3.14.3), `sqlite3`, `jq`, `tmux`, `screen`, `adb` (WiFi only), `ffmpeg` (slow — use `-c copy`), `yt-dlp`, `apache2`, `sudo`, `ps`, `top`, `kill`

---

### What Doesn't Work

| Tool / Feature | Reason |
|---|---|
| `ifconfig` / `ip` | No `/proc/net/dev` |
| `htop` | No `btime` in `/proc/stat` |
| `go build` | Freezes |
| `systemd` | Not supported |
| `nginx` | Known issue |
| MySQL | Crashes |
| Wine | Illegal instruction |
| rustup | i686 platform not supported |
| qemu | Bad system call |
| `strace` | PTRACE not supported |
| `dig` | Use `drill` instead |
| `apt` / `apt-get` | Illegal instruction — wrong package manager; use `apk` |
| sshfs | No FUSE support |
| Audio devices | No audio |
| tcpdump / raw packet capture | No raw socket access |
| Any tool relying on full `/proc` | `/proc/net`, `/proc/cpuinfo`, `/proc/stat` only partially populated |

---

## Performance Characteristics

iSH's x86 emulation overhead is unavoidable. Every instruction passes through the gadget interpreter and syscall translation layer rather than running natively on the device's ARM processor.

- **General overhead:** 5–10× slower than native for compute-heavy workloads.
- **Python:** Noticeably slow for any non-trivial script.
- **pip installs:** Very slow — package resolution and compilation can take minutes for packages that would install in seconds on a native machine.
- **ffmpeg transcoding:** Slow. The recommended workaround is `-c copy` to stream-copy frames without re-encoding.
- **Battery drain:** Significant during heavy CPU use, as the emulator keeps the processor busy.

For interactive shell work — editing files, running git, SSHing into remote servers — the overhead is acceptable. For anything CPU-bound, it becomes a real constraint.

---

## Security Use Cases on iOS

iSH adds a command-line scripting layer to iOS that complements higher-level security tools. The following maps capabilities to practical security workflows.

### What iSH Enables

| Use Case | Tools Available |
|---|---|
| SSH into remote servers | openssh client, mosh, dropbear |
| Running Python security scripts | python3, pip (slow) |
| Basic network recon | nmap (with mods), curl, wget |
| Certificate operations | openssl (including signing) |
| Anonymized traffic routing | tor (SSH + HTTP proxy) |
| Git-based security tooling | git clone, pull, scripted workflows |
| Exploit framework (basic) | metasploit (`msfconsole -n`) |
| SNMP enumeration | snmpwalk |

### What iSH Cannot Do

| Capability | Reason |
|---|---|
| Raw packet capture (tcpdump, Wireshark) | No raw socket access on iOS |
| Network interface monitoring (ifconfig, ip) | No `/proc/net/dev` |
| Kernel-level monitoring | Sandboxed; no kernel access |
| Any tool depending on full `/proc` | `/proc` only partially emulated |
| Process tracing (strace) | PTRACE not supported |

### Position in a Layered iOS Security Platform

iSH is best understood as a **CLI scripting substrate** — the layer that lets you run shell scripts, Python tools, and SSH sessions locally, without needing a remote Linux box for every operation. It fits between polished GUI security apps and a full remote server:

```
[iOS Security Apps]  ←  purpose-built tools (network scanners, VPN, etc.)
[iSH]                ←  local CLI: ssh, python, nmap, git, openssl, tor
[Remote Linux box]   ←  serious workloads: packet capture, kernel tools, Go, Rust
```

For the kinds of workflows covered in an iOS security guide — SSH tunneling, Python-based script execution, certificate inspection, Tor routing, and basic recon — iSH is genuinely useful. It is not a replacement for a proper Linux environment for kernel-level or high-performance security work.

---

## Alternatives on iOS

| Tool | Approach | Best For | Limitations vs. iSH |
|---|---|---|---|
| **a-Shell** | WebAssembly compilation for C/C++ | Stable scripting env; Apple-friendly | No x86 emulation; narrower package ecosystem |
| **Pythonista** | Native Python runtime | Python scripting with iOS integration | Python only; no general Linux shell |
| **Secure Shellfish** | Purpose-built SSH client | SSH file access and terminal sessions | No local Linux environment |
| **Termius** | Full SSH/SFTP client | Polished SSH/SFTP workflows | Subscription-based; no local shell |
| **Remote Linux box (SSH)** | Native Linux on real hardware | All serious security work | Requires external server; not local |

**a-Shell** is the closest architectural peer — it runs locally and offers a shell environment — but uses WebAssembly rather than x86 emulation, which makes it more compatible with Apple's guidelines but limits it to software compiled specifically for that environment. iSH's Alpine Linux userspace gives it a much broader package selection via `apk`.

For SSH-heavy workflows, **Secure Shellfish** or **Termius** are more purpose-fit than iSH's openssh client. For Python-specific tasks, **Pythonista** is significantly faster. iSH's niche is the *full Alpine Linux environment* — the combination of a package manager, multiple languages, and networking tools in a single local app.

---

## Bottom Line

iSH is an impressive engineering achievement: a full Alpine Linux shell running locally on iOS, achieved through a bespoke threaded-code x86 emulator that sidesteps every iOS restriction Apple imposes. The [iSH GitHub project](https://github.com/ish-app/ish) and [wiki](https://github.com/ish-app/ish/wiki/What-works%3F) document a surprisingly large compatibility surface — bash, python, node, ruby, gcc, git, openssh, tor, metasploit, nmap, and more all work.

The honest constraints are:

1. **Performance.** 5–10× slower than native is fine for interactive work; it is a real problem for anything compute-bound.
2. **Missing `/proc`.** A significant chunk of Linux tooling assumes a fully populated `/proc` filesystem. iSH's partial emulation breaks htop, ifconfig, ip, and any network monitoring tool.
3. **No raw sockets.** tcpdump and similar tools are entirely off the table on iOS.
4. **Slow development cadence.** The last stable release was May 2023. The project is maintained but not actively developed at pace.

For a developer or security researcher who needs occasional SSH access, the ability to run a Python script, or wants to experiment with git and shell tooling on an iPhone or iPad, iSH delivers real value at zero cost. For anything requiring raw packet capture, kernel access, Go or Rust compilation, or sustained high-performance workloads, SSH into a real Linux server is the right tool. iSH and a remote Linux box are complementary, not competing.

---

*Sources: [iSH GitHub](https://github.com/ish-app/ish) · [iSH Wiki — What Works](https://github.com/ish-app/ish/wiki/What-works%3F) · [ish.app](https://ish.app) · [HackMag — www-ish](https://hackmag.com/mobile/www-ish) · [The Register — Apple cracks down on terminal apps](https://www.theregister.com/2020/11/09/apple_cracks_down_on_terminal/)*
