# iSH: Linux Shell on iOS — Deep-Dive Technical Report

> **Compiled:** April 2026 | **Sources:** [iSH GitHub](https://github.com/ish-app/ish) · [iSH Wiki](https://github.com/ish-app/ish/wiki/What-works%3F) · [Architecture Docs (Mintlify, March 2026)](https://www.mintlify.com/Phineas1500/ish/architecture/overview) · [The Register](https://www.theregister.com/2020/11/09/apple_cracks_down_on_terminal/) · [Hacker News discussion](https://news.ycombinator.com/item?id=18430031)

---

## TL;DR

- iSH is a free, open-source iOS app that runs a real Alpine Linux shell locally on iPhone/iPad using a usermode **x86 and x86_64** emulator — no VM, no hypervisor, no cloud.
- It works via a **threaded-code interpreter** that translates x86/x86_64 Linux syscalls to iOS/Darwin equivalents in real time. JIT compilation (which Apple prohibits for third-party apps) is never used.
- The emulator implements ~150+ distinct Linux syscalls, including the full signal, socket, threading, timer, and memory management subsystems. Around 20–30 syscalls are stubbed and return `ENOSYS`.
- Performance is 5–10× slower than native; compute-heavy tasks (pip installs, Ruby gems, ffmpeg transcoding) are noticeably sluggish.
- **Background execution** is possible via a `/dev/location` keepalive trick — iSH's virtual location device tells iOS the app is using location services, preventing it from being suspended.
- Security-relevant tools — nmap (`-sT -Pn`), metasploit (`msfconsole -n`), openssh, openssl, tor + proxychains, socat — all work with specific invocation flags.
- `AF_NETLINK` is not implemented, breaking `ifconfig`, `ip`, `ss`, and standard nmap host discovery. Raw sockets are unavailable, blocking tcpdump and raw SYN scans.
- iSH **cannot** run native arm64 Alpine binaries: unsigned ARM binaries would need to execute on the real CPU, which requires Apple code signatures — a constraint that makes x86 emulation the only viable path within App Store rules.
- Last stable App Store release: **v1.3.2 (build 494), May 2023**. The codebase supports x86_64, but no x86_64 App Store build has shipped.

---

## What Is iSH?

[iSH](https://ish.app) is a free, open-source iOS application that provides a fully local Linux shell environment on iPhone and iPad. Rather than connecting to a remote server or running a hypervisor, iSH brings the shell directly onto the device using a custom usermode x86/x86_64 emulator paired with a syscall translation layer. The emulator intercepts x86 Linux syscalls and remaps them to iOS equivalents in real time, allowing standard Linux userspace binaries to run without modification.

The userspace environment is [Alpine Linux](https://alpinelinux.org/) — a minimalist, BusyBox-based distribution — managed via **apk** (Alpine Package Manager). This gives users access to thousands of Linux software packages directly on their device.

iSH was created by **Theodore Dubois (tbodt)** and is maintained as an open-source project on [GitHub](https://github.com/ish-app/ish), where it has accumulated **19,600+ stars** and **1,300+ forks** across 4,242+ commits. The app is free on the App Store, has been downloaded over **631,000 times**, and holds a **4.6–4.8/5 rating**. The latest stable release is **v1.3.2 (build 494)**, published May 2023; beta versions are available via TestFlight. The [Hacker News launch thread](https://news.ycombinator.com/item?id=18430031) generated significant discussion and drove early adoption.

### Codebase Composition

| Language | Share |
|---|---|
| C | 70.0% |
| Objective-C | 21.4% |
| Assembly | 5.4% |
| Swift | 0.8% |

The heavy use of C and hand-written assembly reflects the performance-critical nature of the emulator core. The kernel/ and emu/ directories contain the most architecturally significant code.

---

## Architecture — Deep Dive

### High-Level Design

iSH's architecture is unconventional, shaped entirely by iOS platform restrictions. The [official architecture documentation (Mintlify, March 2026)](https://www.mintlify.com/Phineas1500/ish/architecture/overview) describes the system as providing **"x86/x86_64 CPU instruction emulation using a threaded code interpreter"** — confirming that both 32-bit x86 and 64-bit x86_64 emulation are now part of the codebase, though only x86 is in the current App Store release.

The three layers are:

```
┌─────────────────────────────────────────┐
│         Linux Userspace (Alpine)        │  ← apk packages, shell, tools
├─────────────────────────────────────────┤
│     x86/x86_64 Emulator + Syscall       │  ← threaded-code interpreter,
│         Translation Layer              │    interrupt dispatch, CPU state
├─────────────────────────────────────────┤
│     iOS / Darwin Host (ARM64 CPU)       │  ← real hardware, sandboxed
└─────────────────────────────────────────┘
```

### Threaded Code Gadgets (Not JIT)

Apple prohibits JIT compilation on iOS for third-party apps — only Safari's JavaScript engine holds that privilege. iSH therefore uses a **custom interpreter** built around *threaded code*, similar to how Forth implementations operate. Instead of compiling x86 instructions to native ARM at runtime, the interpreter generates an **array of function pointers**. Each entry, called a "gadget," executes a small operation and ends with a tailcall to the next gadget in the array. This is approximately **3–5× faster** than a naive switch-dispatch interpreter and requires no writable+executable memory mapping — the critical property that keeps it within Apple's rules.

Gadgets are written mostly in hand-crafted assembly for maximum throughput, as visible in the `emu/` directory of the [iSH source tree](https://github.com/ish-app/ish).

### Exact Data Flow

This is the complete path from a user typing a command to a result appearing on screen, as documented in the [architecture overview](https://www.mintlify.com/Phineas1500/ish/architecture/overview):

1. User types a command in the iSH terminal.
2. The x86 emulator executes the program's machine instructions, maintaining full CPU state (registers, flags, segment registers).
3. When the program makes a Linux syscall, it triggers an interrupt:
   - x86 (32-bit): `int 0x80` → dispatched as `INT_SYSCALL`
   - x86_64 (64-bit): `syscall` instruction → dispatched as `INT_SYSCALL64`
4. The kernel layer translates the Linux syscall to an iOS/Darwin equivalent, or emulates it in software.
5. The filesystem layer handles any file-related requests (SQLite fake-DB, real passthrough FS, or a special virtual filesystem like `/proc` or `/dev`).
6. The result is written back into emulated memory and returned via CPU registers (`eax` for x86, `rax` for x86_64).

### Memory Management Subsystem

iSH implements a software **MMU (Memory Management Unit)** and **TLB (Translation Lookaside Buffer)**:

| Component | Role |
|---|---|
| MMU | Translates guest virtual addresses → host memory pointers |
| TLB | Caches recent address translations to avoid repeated MMU lookups |
| Page fault handler | Triggered via `INT_GPF` interrupt; delivers `SIGSEGV` to the guest if unhandled |
| TLB cache | Key performance optimization — frequently accessed pages skip the full MMU translation |

The TLB is a software structure maintained by iSH. Because the x86 guest has its own address space laid on top of the iOS process address space, every memory access conceptually requires a translation. The TLB makes this fast for hot pages.

### FPU, SSE, and MMX Emulation

The source tree includes dedicated emulation modules beyond the basic x86 integer core:

| File | Purpose |
|---|---|
| `emu/fpu.c` | x87 Floating Point Unit emulation |
| `emu/vec.c` | SSE / SSE2 vector instruction emulation |
| `emu/mmx.c` | MMX integer SIMD instruction emulation |

These modules are why software like Python (which uses SSE2 internally), compiled C code with floating-point, and many libraries work correctly. The emulator covers not just the basic x86 integer instruction set but the full modern x86 instruction surface, including packed vector operations.

### Hybrid Filesystem Design

iSH uses a hybrid approach to storage that bridges the gap between Linux's POSIX-rich filesystem model and iOS's sandboxed filesystem:

| Layer | Mechanism | Purpose |
|---|---|---|
| SQLite database | Stores UNIX metadata (permissions, ownership, inodes) | iOS filesystem doesn't natively support POSIX permission bits or arbitrary ownership |
| Real filesystem passthrough | Actual file data stored in iSH's iOS sandbox directory | Efficient storage of file content |
| Virtual `/proc` | Software-emulated entries | Provides partial `/proc/cpuinfo`, `/proc/stat`, `/proc/net` |
| Virtual `/dev` | Special device files | `/dev/null`, `/dev/random`, `/dev/urandom`, `/dev/location` |
| File Provider extension | iOS Files app integration | Lets you browse iSH's filesystem from the Files app |

The **File Provider extension** is particularly important: it integrates iSH's root filesystem into the iOS Files app, so you can access files from iSH in any Files-aware iOS app and vice versa.

The `mount -t ios . <folder>` command takes this further — it opens the iOS file picker and mounts any iOS file provider location (iCloud Drive, On My iPhone, external storage) directly into iSH's filesystem namespace. This is the primary bridge to the rest of iOS storage and enables workflows like git-syncing an Obsidian vault.

### Why Not Native ARM64?

[GitHub issue #2556 (April 2025)](https://github.com/ish-app/ish/issues/2556) asked directly why iSH doesn't run native arm64 Alpine Linux, which would be dramatically faster. The answer is a hard architectural constraint:

1. All ARM64 binaries executing on the device's real CPU must be **Apple code-signed**. Downloaded Alpine packages are not signed.
2. Without JIT, there is no way to patch syscalls in unsigned binaries at runtime — you cannot intercept and redirect system calls in code that runs directly on the hardware.
3. The x86 emulation approach works precisely because **iSH intercepts all x86 instructions before they hit the ARM CPU**. Unsigned x86 code never "runs" on the hardware; it is interpreted in iSH's address space, which is itself a signed iOS app.
4. Adding JIT to emit ARM64 code dynamically would require the `MAP_JIT` entitlement and writable+executable memory, which Apple does not grant to third-party apps outside of Safari.

This is the fundamental architectural constraint that makes the x86 emulation approach the only viable path within Apple's App Store rules — and the reason the project cannot simply switch to faster native execution.

---

## Syscall Implementation — Complete Reference

The syscall table lives at [`kernel/calls.c`](https://github.com/ish-app/ish/blob/master/kernel/calls.c) in the iSH source tree. iSH implements approximately **150+ distinct syscalls**. The following tables organize them by subsystem.

### Interrupt Dispatch Code

When a syscall interrupt fires, the handler reads the syscall number and arguments from the CPU register state and dispatches into the table. The core dispatch logic (from source):

```c
void handle_interrupt(int interrupt) {
    struct cpu_state *cpu = &current->cpu;
    if (interrupt == INT_SYSCALL) {
        unsigned syscall_num = cpu->eax;
        int result = syscall_table[syscall_num](
            cpu->ebx, cpu->ecx, cpu->edx,
            cpu->esi, cpu->edi, cpu->ebp);
        cpu->eax = result;
    }
    if (interrupt == INT_SYSCALL64) {
        unsigned syscall_num = cpu->rax;
        // x86_64 argument order: rdi, rsi, rdx, r10, r8, r9
        int64_t result = syscall_table[syscall_num](
            cpu->rdi, cpu->rsi, cpu->rdx,
            cpu->r10, cpu->r8, cpu->r9);
        cpu->rax = result;
    }
}
```

Note the difference in argument registers between the x86 ABI (`ebx/ecx/edx/esi/edi/ebp`) and the x86_64 ABI (`rdi/rsi/rdx/r10/r8/r9`). Both are handled in the same interrupt handler via the `INT_SYSCALL` vs `INT_SYSCALL64` branch.

### File & I/O Syscalls

| Syscall | Number | Notes |
|---|---|---|
| sys_read | 3 | Implemented |
| sys_write | 4 | Implemented |
| sys_open | 5 | Implemented |
| sys_close | 6 | Implemented |
| sys_lseek | 19 | Implemented |
| sys_readv / sys_writev | 145 / 146 | Implemented |
| sys_pread / sys_pwrite | 180 / 181 | Implemented |
| sys_sendfile | 187 | Implemented |
| sys_sendfile64 | 239 | Implemented |
| sys_mmap | 90 | Implemented |
| sys_munmap | 91 | Implemented |
| sys_mmap2 | 192 | Implemented (x86 32-bit mmap) |
| sys_openat | 295 | Implemented |
| sys_splice | 313 | Implemented |
| sys_copy_file_range | 377 | Implemented |
| sys_statx | 383 | Implemented |

### Process Syscalls

| Syscall | Number | Notes |
|---|---|---|
| sys_fork | 2 | Implemented (emulated, not native fork) |
| sys_execve | 11 | Implemented |
| sys_exit | 1 | Implemented |
| sys_exit_group | 252 | Implemented |
| sys_waitpid | 7 | Implemented |
| sys_wait4 | 114 | Implemented |
| sys_waitid | 284 | Implemented |
| sys_clone | 120 | Implemented (threading) |
| sys_vfork | 190 | Implemented |
| sys_kill | 37 | Implemented |
| sys_tkill | 238 | Implemented |
| sys_tgkill | 270 | Implemented |

### Memory Syscalls

| Syscall | Number | Notes |
|---|---|---|
| sys_brk | 45 | Implemented |
| sys_mprotect | 125 | Implemented |
| sys_mlock | 150 | Implemented |
| sys_mremap | 163 | Implemented |
| sys_madvise | 219 | Implemented |
| sys_fallocate | 324 | Implemented |

### Signal Syscalls

| Syscall | Number | Notes |
|---|---|---|
| sys_sigreturn | 119 | Implemented |
| sys_rt_sigreturn | 173 | Implemented |
| sys_rt_sigaction | 174 | Implemented |
| sys_rt_sigprocmask | 175 | Implemented |
| sys_rt_sigpending | 176 | Implemented |
| sys_rt_sigtimedwait | 177 | Implemented |
| sys_rt_sigsuspend | 179 | Implemented |
| sys_sigaltstack | 186 | Implemented |

### Socket Syscalls

Sockets are dispatched via `socketcall` [102] on x86 32-bit, or directly on x86_64. Key individual socket syscalls:

| Syscall | Number | Notes |
|---|---|---|
| sys_socket | 359 | Implemented (TCP/UDP; AF_NETLINK **not implemented**) |
| sys_bind | 361 | Implemented |
| sys_connect | 362 | Implemented |
| sys_listen | 363 | Implemented |
| sys_accept | (via socketcall) | Implemented |
| sys_accept4 | 364 | **Stubbed** — returns ENOSYS |
| sys_getsockopt | 365 | Implemented |
| sys_setsockopt | 366 | Implemented |
| sys_getsockname | 367 | Implemented |
| sys_getpeername | 368 | Implemented |
| sys_sendto | 369 | Implemented |
| sys_sendmsg | 370 | Implemented |
| sys_recvfrom | 371 | Implemented |
| sys_recvmsg | 372 | Implemented |
| sys_shutdown | 373 | Implemented |
| sys_sendmmsg | 345 | Implemented |

### Filesystem Syscalls

| Syscall | Number | Notes |
|---|---|---|
| sys_mount | 21 | Implemented (supports `-t ios`) |
| sys_umount2 | 52 | Implemented |
| sys_chroot | 61 | Implemented |
| sys_statfs / sys_fstatfs | 99 / 100 | Implemented |
| sys_getdents | 141 | Implemented |
| sys_getdents64 | 220 | Implemented |
| sys_statfs64 / sys_fstatfs64 | 268 / 269 | Implemented |
| sys_stat64 | 195 | Implemented |
| sys_lstat64 | 196 | Implemented |
| sys_fstat64 | 197 | Implemented |
| sys_fstatat64 | 300 | Implemented |

### Timer Syscalls

| Syscall | Number | Notes |
|---|---|---|
| sys_nanosleep | 162 | Implemented |
| sys_setitimer | 104 | Implemented |
| sys_clock_gettime | 265 | Implemented |
| sys_clock_settime | 264 | Implemented |
| sys_clock_getres | 266 | Implemented |
| sys_timerfd_create | 322 | Implemented |
| sys_timerfd_settime | 325 | Implemented |
| sys_timer_create | 259 | Implemented |
| sys_timer_settime | 260 | Implemented |

### Threading & Synchronization Syscalls

| Syscall | Number | Notes |
|---|---|---|
| sys_futex | 240 | Implemented — core of pthreads |
| sys_set_tid_address | 258 | Implemented |
| sys_gettid | 224 | Implemented |
| sys_sched_yield | 158 | Implemented |
| sys_sched_setaffinity | 241 | Implemented |
| sys_sched_getaffinity | 242 | Implemented |
| sys_set_thread_area | 243 | Implemented (TLS setup) |
| sys_epoll_create | 254 / 329 | Implemented |
| sys_epoll_ctl | 255 | Implemented |
| sys_epoll_wait | 256 | Implemented |
| sys_epoll_pwait | 319 | Implemented |
| sys_eventfd | 323 | Implemented |
| sys_eventfd2 | 328 | Implemented |

### Stubbed / Missing Syscalls (Return ENOSYS)

These syscalls are not implemented — they return `ENOSYS` and break tools that depend on them:

| Syscall | Number | Impact |
|---|---|---|
| inotify_init | 291 | File watching tools (inotifywait, watchman) don't work |
| inotify_init1 | 332 | Same — alternate init variant also stubbed |
| io_setup | 245 | AIO (async I/O) stubbed — heavy async I/O apps fail |
| setfsuid / setfsgid | 215 / 216 | Some privilege-dropping code paths fail silently |
| xattr syscalls | 226–237 | Extended attributes entirely non-functional |
| accept4 | 364 | Server apps using `accept4()` instead of `accept()` fail |
| membarrier | 375 | Silently stubbed — most apps don't notice |
| AF_NETLINK socket family | — | `ip`, `ifconfig`, `ss`, nmap host discovery all fail |

The **AF_NETLINK** gap is the most impactful: `socket(AF_NETLINK, 3, 0)` returns `EINVAL`. Any tool that uses netlink to enumerate interfaces or routing tables hits this immediately. This includes nmap's default host discovery path, which is why `-Pn` is required on iSH.

---

## Background Execution — The `/dev/location` Trick

iOS aggressively suspends backgrounded apps within seconds. iSH implements a specific workaround for long-running background processes.

### How It Works

iSH exposes a virtual device at `/dev/location`. Reading from it causes iSH to register as a location-services client with iOS. iOS permits apps that are actively using location services to continue running in the background. The location data itself is discarded — the read is purely a keepalive signal.

The feature was requested in [GitHub issue #249 (January 2019)](https://github.com/ish-app/ish/issues/249) and implemented by tbodt by October 2019 via a commit with the message: *"Add location tracking device — Supports tracking your location in the background, which has the nice side effect of keeping everything in the app running in the background. #249"*

To activate:

```sh
cat /dev/location > /dev/null &
```

Run this at the start of any session that needs to survive backgrounding. The `&` sends it to the background; the process continues reading location data and silently discarding it, keeping iSH alive.

### Practical Background Session Script

```sh
#!/bin/ash
# Keep iSH alive in background
cat /dev/location > /dev/null &

# Example: proxy VPN traffic through iPhone cellular
apk add socat
socat tcp-listen:51821,reuseaddr,fork tcp:<vpn_server>:<vpn_port>
```

### Alternative (iPad Only)

Split View — keeping iSH visible alongside Safari or another app in iPad's Split View prevents iOS from suspending it. This works without the `/dev/location` trick but requires the iPad to remain in Split View.

---

## Security Tool Deep Dives

### nmap — Why Standard Invocation Fails

Standard nmap tries to use `AF_NETLINK` to discover network interfaces before scanning. On iSH, `socket(AF_NETLINK, 3, 0)` returns `EINVAL` — the socket family is not implemented. This causes nmap to abort before reaching the scan phase.

The solution is to bypass both host discovery and raw socket use entirely. See also [GitHub issue #166](https://github.com/ish-app/ish/issues/166) and the [detailed nmap on iPhone guide](https://ku.nz/blog/nmaponiphone.html):

```sh
nmap -sT -Pn <target_ip>
```

- `-Pn` — skip host discovery (no ICMP ping, no netlink interface lookup)
- `-sT` — TCP connect scan (uses `connect()` syscall, not raw SYN packets)

This bypasses both the AF_NETLINK limitation and the raw socket restriction. Full network range scanning with `/24` subnets is extremely slow over x86 emulation; targeted single-IP scans are practical.

```sh
# Common service scan on a single target
nmap -sT -Pn -p 22,80,443,8080,8443 <target_ip>

# Version detection (slow but works)
nmap -sT -Pn -sV -p 22,80,443 <target_ip>

# With Tor routing via proxychains
proxychains nmap -sT -Pn <target_ip>
```

**What still doesn't work:** SYN scan (`-sS`), UDP scan (`-sU`), OS detection (`-O`), and any module requiring raw sockets or ICMP. These hit the iOS raw socket restriction, not the iSH emulation layer.

### Metasploit Framework — Setup and Caveats

Metasploit runs on iSH but requires bypassing its PostgreSQL database dependency and accepting extremely slow performance due to Ruby running under x86 emulation.

**Installation:**

```sh
apk update && apk upgrade
apk add ruby ruby-dev git curl bash openssl-dev build-base libffi-dev \
    postgresql-dev sqlite-dev
gem install bundler
git clone https://github.com/rapid7/metasploit-framework.git
cd metasploit-framework
bundle install
```

`bundle install` may take 30–60 minutes on a modern iPhone due to gem compilation under emulation.

**Launch (no database):**

```sh
./msfconsole -n
```

The `-n` flag is critical. Without it, metasploit tries to connect to a PostgreSQL server, which does not work on iSH. Running with `-n` disables workspace and loot storage features but allows the full exploit/auxiliary/payload module system to function. Basic scanning, exploitation, and payload generation all work; anything requiring persistent session storage to a database does not.

**Performance note:** Expect msfconsole startup to take several minutes. Module searches and use commands are slow. For practical penetration testing, SSH into a remote Linux box and run metasploit there; use iSH as the SSH client.

### Tor + Proxychains — Anonymous Routing

```sh
apk add tor proxychains-ng

# Start Tor daemon
tor &

# Edit proxychains config to use Tor's SOCKS5 proxy
# /etc/proxychains.conf: add/replace the proxy line with:
#   socks5 127.0.0.1 9050

# Use proxychains to route any tool through Tor
proxychains curl https://check.torproject.org
proxychains nmap -sT -Pn <target>
proxychains ssh user@host
```

Tor on iSH works well for SOCKS5 proxying of TCP traffic. DNS resolution via proxychains goes through Tor's DNS resolver. Note that Tor's performance is already limited; running under x86 emulation adds further latency.

### VNC Server — Graphical Desktop on iPhone

iSH can run a headless X11 server via Xvfb and expose it over VNC, giving a graphical Alpine Linux desktop accessible from a VNC client app on the same device:

```sh
apk add xvfb x11vnc i3 xterm

# Start virtual framebuffer display
Xvfb :1 -screen 0 1024x768x16 &

# Start window manager on virtual display
DISPLAY=:1 i3 &

# Start VNC server (no password, localhost only)
x11vnc -display :1 -nopw -listen localhost -xkb &
```

Then connect from a VNC client app (e.g., "Remoter VNC" from the App Store) to `localhost`. This gives a full graphical Alpine Linux desktop on an iPhone — genuinely functional, though slow due to the emulation overhead. Useful for GUI tools that don't have CLI equivalents.

### socat — Carrier Tethering Bypass

A documented hack using iSH + socat can bypass carrier tethering restrictions on unjailbroken iPhones, [as discussed on Reddit](https://www.reddit.com/r/NoContract/comments/1euwy0p/). The mechanism: route VPN traffic from a laptop through iSH's socket layer rather than iOS's native hotspot path, bypassing iOS's tethering detection.

```sh
apk add socat

# Keep iSH running in background
cat /dev/location > /dev/null &

# Forward VPN traffic: laptop connects to iPhone port 51821,
# iSH forwards it to your VPN server
socat tcp-listen:51821,reuseaddr,fork tcp:<vpn_server>:<vpn_port>
```

The laptop connects to the iPhone's IP on port 51821. iSH receives the TCP connection and forwards it to the VPN server. The PC's VPN client tunnels through this connection, routing internet traffic through the phone's cellular connection. iOS's tethering detection never triggers because the traffic flows through iSH's `connect()`/`accept()` syscall path, not the native Personal Hotspot interface.

**Critical limitation:** This only works with TCP-wrapped VPNs. OpenVPN in TCP mode and WireGuard-over-wstunnel (which wraps UDP in TCP) work; native UDP WireGuard and UDP-based OpenVPN do not, because iSH cannot do UDP forwarding to arbitrary external IPs with the same transparency.

### Obsidian Git Sync — iOS Files Integration

iSH's iOS file provider integration enables git-based sync workflows directly on files in iOS's sandboxed storage:

```sh
# Create a mount point
mkdir ~/vault

# Mount an iOS file provider location (opens iOS file picker)
mount -t ios . vault

# Now run git inside the mounted iOS directory
cd vault
git init   # or git clone <remote>
git pull
git add .
git commit -m "sync"
git push
```

This is noteworthy because no other iOS app can run arbitrary git operations on files inside iOS storage locations like iCloud Drive or "On My iPhone." iSH is the bridge that makes this possible, as documented in the [iSH wiki](https://github.com/ish-app/ish/wiki/What-works%3F).

---

## Compatibility Reference

Drawn from the [official iSH wiki — What Works](https://github.com/ish-app/ish/wiki/What-works%3F).

### Tools That Work

#### Shells & Editors

`bash`, `zsh`, `fish`, `vim`, `nvim`, `nano`, `emacs`, `vi`, `micro`

#### Languages & Runtimes

| Tool | Status | Notes |
|---|---|---|
| Python 3 | Works | Slow |
| pip | Works | Very slow; compilation under emulation |
| Node.js | Works | |
| Ruby / irb / gem | Works | |
| Perl | Works | |
| PHP 7 + 8 | Works | |
| R | Works | |
| gcc / clang | Works | |
| gawk | Works | |

#### Networking & SSH

| Tool | Status | Notes |
|---|---|---|
| curl (HTTPS) | Works | |
| wget (HTTPS) | Works | |
| openssh client | Works | |
| openssh server | Works | SHA-1 only (not SHA-2) |
| mosh | Works | |
| dropbear client | Works | |
| dropbear server | Works | Requires `-E` flag, port >1024 |
| lftp | Works | |
| tor | Works | TCP proxy via SOCKS5 |
| resolvconf | Works | |
| socat | Works | Key tool for port forwarding and proxying |

#### Security Tools

| Tool | Status | Invocation | Notes |
|---|---|---|---|
| nmap | Works with mods | `nmap -sT -Pn <target>` | No AF_NETLINK; no raw sockets |
| metasploit-framework | Works (slow) | `msfconsole -n` | No PostgreSQL; no database features |
| tor | Works | `tor &` | SOCKS5 proxy on 9050 |
| proxychains-ng | Works | `proxychains <cmd>` | Route tools through Tor |
| openssl | Works | | Including certificate signing |
| openssh | Client + server | — | Server: SHA-1, port >1024 |
| dropbear | Works | `-E` flag | |
| snmpwalk | Works | | |
| socat | Works | | Port forwarding, proxying |
| x11vnc + Xvfb | Works | See VNC section | Graphical desktop |

#### Dev & Utility Tools

`git`, `gcc`, `clang`, `make`, `gdb` (Alpine 3.14.3), `sqlite3`, `jq`, `tmux`, `screen`, `adb` (WiFi only), `ffmpeg` (slow — use `-c copy`), `yt-dlp`, `apache2`, `sudo`, `ps`, `top`, `kill`

---

### Tools That Don't Work

| Tool / Feature | Root Cause |
|---|---|
| `ifconfig` / `ip` / `ss` | AF_NETLINK not implemented; no `/proc/net/dev` |
| `htop` | No `btime` field in `/proc/stat` |
| `go build` | Freezes (goroutine scheduler issue) |
| `systemd` | Not supported |
| `nginx` | Known issue |
| MySQL | Crashes |
| Wine | Illegal instruction |
| rustup | i686 platform not supported by rustup |
| qemu | Bad system call |
| `strace` | PTRACE not implemented |
| `dig` | Use `drill` instead |
| `apt` / `apt-get` | Wrong package manager for Alpine; use `apk` |
| sshfs | No FUSE support |
| Audio | No audio device emulation |
| tcpdump / Wireshark | No raw socket access on iOS |
| nmap default (without `-Pn`) | AF_NETLINK missing; host discovery fails |
| inotifywait / watchman | inotify syscalls stubbed |
| Async I/O heavy apps | `io_setup` (AIO) stubbed |
| xattr tools | xattr syscalls 226–237 all stubbed |
| Any tool relying on full `/proc` | `/proc` only partially emulated |

---

## iOS Platform Restrictions — Impact Table

| iOS Restriction | Root Mechanism | What It Breaks in iSH |
|---|---|---|
| No JIT | `MAP_JIT` entitlement denied for 3rd-party apps | Forces threaded-code interpreter; no native-speed execution |
| No raw sockets | iOS sandbox | tcpdump, nmap SYN scan, OS detection |
| No `AF_NETLINK` | Not implemented (would require kernel cooperation) | ifconfig, ip, ss, nmap host discovery |
| No FUSE | iOS sandbox | sshfs |
| No PTRACE | iOS sandbox | strace, gdb attach-to-process |
| Partial `/proc` | Software emulation limits | htop, tools reading `/proc/net`, `/proc/stat` |
| App sandbox | iOS design | Cannot access other app data |
| Background suspend | iOS process lifecycle | Requires `/dev/location` keepalive |
| ARM64 code signing | All executables must be Apple-signed | Can't run unsigned ARM binaries; forces x86 emulation |

In 2020, Apple's App Store review team flagged iSH for allowing user code execution and nearly removed it from the store. iSH appealed and Apple allowed it to remain — but the incident highlighted the tension between a local Linux emulator and App Store policies ([The Register, November 2020](https://www.theregister.com/2020/11/09/apple_cracks_down_on_terminal/)).

---

## Performance Characteristics

iSH's x86 emulation overhead is unavoidable. Every instruction passes through the gadget interpreter; every syscall goes through the translation layer.

| Workload | Overhead vs. Native | Notes |
|---|---|---|
| Interactive shell (editing, git) | ~2–3× | Acceptable |
| Python scripts | 5–10× | Noticeable for non-trivial code |
| pip install (with compilation) | 10–30× | Can take minutes vs. seconds |
| Ruby gems (bundle install) | 10–30× | Metasploit install takes 30–60 min |
| ffmpeg transcoding | 10–20× | Use `-c copy` to stream-copy |
| nmap TCP connect scan | 3–5× | Slower but usable for targeted scans |
| SSH client operations | ~2× | Mostly network-bound; emulation overhead minor |

The TLB caching in iSH's MMU subsystem partially mitigates memory access overhead for hot code paths. The threaded-code gadget design handles branch-heavy code better than a naive switch interpreter. Still, the fundamental constraint — interpreting every instruction rather than executing it natively — cannot be optimized away.

---

## Development Status (2025–2026)

| Metric | Status |
|---|---|
| Last stable App Store release | v1.3.2 (build 494), May 2023 |
| x86_64 support | In codebase ([arch docs, March 2026](https://www.mintlify.com/Phineas1500/ish/architecture/overview)); not yet in App Store release |
| Main developer (tbodt) | Less active; project not abandoned |
| Community | Active: r/ish subreddit, Discord server |
| Architecture documentation | Community-maintained Mintlify docs updated March 2026 |
| GitHub stars | 19,600+ |
| Open source | Yes; contributions via PRs accepted |
| TestFlight | Beta available |

The project is in a maintenance phase rather than active feature development. The most significant pending capability is an x86_64 App Store release — the codebase supports it, but no release has shipped. The [architecture docs (March 2026)](https://www.mintlify.com/Phineas1500/ish/architecture/overview) indicate community documentation efforts are ongoing, suggesting the project remains active even if slowly.

---

## Practical Setup Guide — Security Use

Full quick-start from a fresh iSH App Store install.

### Step 1: Bootstrap apk

The App Store version may ship without a working `apk`. Bootstrap it:

```sh
wget -qO- http://dl-cdn.alpinelinux.org/alpine/v3.12/main/x86/apk-tools-static-2.10.5-r1.apk \
  | tar -xz sbin/apk.static && ./sbin/apk.static add apk-tools && rm sbin/apk.static
```

### Step 2: Update Package Index

```sh
apk update && apk upgrade
```

### Step 3: Install Core Tools

```sh
apk add bash git curl wget openssl openssh nmap tor proxychains-ng \
    python3 py3-pip tmux socat ruby ruby-dev build-base
```

### Step 4: Enable Background Execution

```sh
cat /dev/location > /dev/null &
```

Run this immediately in any session that needs to survive backgrounding. Add it to your shell's startup script (e.g., `~/.profile`) to automate it.

### Step 5: nmap Scanning

```sh
# Single host, common ports
nmap -sT -Pn -p 22,80,443,8080,8443 <target_ip>

# With version detection
nmap -sT -Pn -sV <target_ip>

# Via Tor (after `tor &`)
proxychains nmap -sT -Pn <target_ip>
```

### Step 6: SSH Server

```sh
apk add openssh
ssh-keygen -A          # generate host keys
/usr/sbin/sshd -D -p 2222 &
# From another device on the same network:
#   ssh -p 2222 root@<iphone_local_ip>
```

### Step 7: Set Up tmux for Persistent Sessions

```sh
apk add tmux
tmux new -s main       # new session
# Detach: Ctrl-b d
# Reattach: tmux attach -t main
```

Combine with the `/dev/location` keepalive: start tmux, activate the location keepalive inside it, and all panes survive backgrounding.

### Step 8: Mount iOS Files

```sh
mkdir ~/ios_files
mount -t ios . ios_files   # opens iOS file picker
ls ~/ios_files             # browse the mounted location
```

---

## Alternatives on iOS

| Tool | Approach | Best For | Limitations vs. iSH |
|---|---|---|---|
| **a-Shell** | WebAssembly compilation | Stable scripting; Apple-friendly | No x86 emulation; narrower ecosystem |
| **Pythonista** | Native Python runtime | Python scripting with iOS integration | Python only; no general Linux shell |
| **Secure Shellfish** | Purpose-built SSH client | SSH file access and terminal sessions | No local Linux environment |
| **Termius** | Full SSH/SFTP client | Polished SSH/SFTP workflows | Subscription-based; no local shell |
| **Remote Linux box (SSH)** | Native Linux on real hardware | All serious security work | Requires external server; not local |

**a-Shell** is the closest architectural peer — local shell, no cloud — but uses WebAssembly rather than x86 emulation, limiting it to software compiled for that environment. iSH's Alpine Linux userspace via `apk` has a much broader package selection. For SSH-heavy workflows, **Secure Shellfish** or **Termius** are more purpose-fit. For Python-specific tasks, **Pythonista** is significantly faster. iSH's niche is the *complete Alpine Linux environment*: package manager, multiple languages, networking tools, and full POSIX shell, in a single free local app.

---

## Bottom Line

iSH is a remarkable engineering achievement: a full Alpine Linux shell running locally on iOS, achieved through a bespoke threaded-code x86/x86_64 interpreter that sidesteps every iOS restriction Apple imposes. The combination of ~150+ implemented Linux syscalls, a hybrid SQLite+passthrough filesystem, software FPU/SSE/MMX emulation, and the `/dev/location` background keepalive trick gives it a surprisingly large practical surface area.

The hard constraints are:

1. **Performance.** 5–10× slower than native is acceptable for interactive work; it is a real constraint for compute-bound tasks. Ruby/Python compilation times become significant.
2. **AF_NETLINK gap.** The absence of netlink socket support breaks `ifconfig`, `ip`, `ss`, and standard nmap host discovery. All of these require workarounds or replacements.
3. **No raw sockets.** tcpdump and raw SYN scanning are entirely unavailable — an iOS-level restriction iSH cannot work around.
4. **Stubbed syscalls.** inotify, AIO, xattr, and `accept4` return `ENOSYS`. Tools that depend on these silently fail or error.
5. **Slow development.** Last stable release was May 2023. The x86_64 codebase is ready but unshipped.

For security research, iSH is genuinely useful as a **CLI substrate on iOS**: running Python tools, SSH sessions, nmap targeted scans, Tor routing, socat port forwarding, and git operations on iOS files. It is not a replacement for a proper Linux environment for raw packet capture, kernel-level work, or sustained high-performance workloads. iSH and a remote Linux box are complementary — iSH provides the local CLI layer, the remote box provides everything that requires real kernel access.

---

*Sources: [iSH GitHub](https://github.com/ish-app/ish) · [iSH Wiki — What Works](https://github.com/ish-app/ish/wiki/What-works%3F) · [Architecture Docs — Mintlify, March 2026](https://www.mintlify.com/Phineas1500/ish/architecture/overview) · [kernel/calls.c — Syscall Table](https://github.com/ish-app/ish/blob/master/kernel/calls.c) · [Background Execution Issue #249](https://github.com/ish-app/ish/issues/249) · [ARM64 Issue #2556](https://github.com/ish-app/ish/issues/2556) · [nmap Issue #166](https://github.com/ish-app/ish/issues/166) · [nmap on iPhone Guide](https://ku.nz/blog/nmaponiphone.html) · [Tethering Hack (Reddit)](https://www.reddit.com/r/NoContract/comments/1euwy0p/) · [The Register — Apple Cracks Down on Terminal Apps](https://www.theregister.com/2020/11/09/apple_cracks_down_on_terminal/) · [Hacker News Launch Discussion](https://news.ycombinator.com/item?id=18430031)*
