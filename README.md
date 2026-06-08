# Buffer Overflow (Server-Side) — Demonstration & Defence

A self-contained, **localhost-only** web application that demonstrates a **real
buffer overflow in native C** running behind a web server, and contrasts the
**exploitation impact** (crash + memory corruption) with the **prevention**
techniques (bounds checking, stack canary / FORTIFY_SOURCE, ASLR/NX, memory-safe
languages).

---

## Table of contents
1. [What this demo is](#1-what-this-demo-is)
2. [The theory in brief](#2-the-theory-in-brief)
3. [How the system works](#3-how-the-system-works)
4. [Every file explained](#4-every-file-explained)
5. [The C program explained](#5-the-c-program-explained-nativebufferdemoc)
6. [The compiler flags explained](#6-the-compiler-flags-explained-nativemakefile)
7. [Installing Docker](#7-installing-docker)
8. [Building & deploying](#8-building--deploying)
9. [How to demonstrate (step by step)](#9-how-to-demonstrate-step-by-step)
10. [Proving it is real (backend evidence)](#10-proving-it-is-real-backend-evidence)
11. [Viewing logs in the container](#11-viewing-logs-in-the-container)
12. [Prevention techniques](#12-prevention-techniques)
13. [Ties to real-world attacks](#13-ties-to-real-world-attacks)
14. [Troubleshooting](#14-troubleshooting)
15. [Viva talking points](#15-viva-talking-points)

---

## 1. What this demo is

A web page with four buttons. Each button sends your input to a small **native C
program** that runs on the server as an **isolated subprocess**. Depending on the
input and which version of the program runs, you observe one of four outcomes:

| # | Button | What it shows |
|---|---|---|
| ① | Exploitation — Crash | Oversized input overruns a 64-byte buffer → the server process **crashes (SIGSEGV)**. Availability/DoS impact. |
| ② | Exploitation — Corruption | A smaller overflow overwrites an **adjacent variable**. Integrity impact. |
| ③ | Prevention — Bounds check | The same oversized input is **rejected** before any copy. No overflow. |
| ④ | Prevention — Compiler hardening | The **same unsafe code**, compiled with a stack canary + FORTIFY_SOURCE, is **detected and safely aborted**. |

Because the risky C code runs in a child process, scenario ① does **not** take
down the web server — Flask reports the crash and keeps serving. That isolation
is itself a defensive technique for running untrusted/native code.

---

## 2. The theory in brief

A local array such as `char buffer[64];` lives on the program **stack**, inside
the current function's *stack frame*. That frame also stores the **return
address** — where the CPU resumes when the function finishes.

```
  higher memory addresses
  ┌──────────────────────┐
  │  return address      │ ← overwrite this and the program jumps to garbage → crash
  │  saved frame pointer │
  │  buffer[63]          │
  │     ...              │ ← strcpy writes upward from buffer[0]
  │  buffer[0]           │
  └──────────────────────┘
  lower memory addresses
```

`strcpy(buffer, input)` copies bytes **until it reaches a NUL terminator**, with
**no check** that they fit. If `input` is longer than the buffer, the surplus
bytes spill past `buffer` into the saved frame pointer and return address. When
the function returns, the CPU loads the corrupted return address and the process
dies with **SIGSEGV** (scenario ①).

For scenario ②, the variables sit in a `struct { char buf[16]; int authorized; }`.
Struct members are laid out at increasing addresses in declaration order, so
overflowing `buf` deterministically writes into `authorized` — proving the
overflow **crossed a boundary and corrupted neighbouring data**. That
boundary-crossing corruption is exactly what distinguishes a buffer overflow from
mere memory *exhaustion* (which never overwrites anything).

**Why Java can't do this:** the JVM bounds-checks every array access and has no
raw pointers, so an overflow throws an exception instead of corrupting memory.
That is why this demo uses C — only a memory-*unsafe* language can reproduce a
real buffer overflow.

---

## 3. How the system works

```
  Browser (your machine)
      │  HTTP (JSON) on localhost:5001
      ▼
  Flask web app  (app.py)          ← Python; the "web server"
      │  subprocess.run([...])      ← runs the C program as a child process
      ▼
  Native C binary (native/bufferdemo_vuln or _hardened)
      │  returns exit code + stdout/stderr (or is killed by a signal)
      ▼
  Flask classifies the outcome, logs it, returns JSON
      │
      ▼
  Browser renders the result + a live backend-log panel
```

Everything runs inside one Docker container on your laptop. Nothing is exposed to
the network beyond the single port you publish.

---

## 4. Every file explained

```
buffer-overflow-demo/
├── Dockerfile            # recipe to build the container image
├── requirements.txt      # Python dependencies (just Flask)
├── app.py                # the Flask web server + subprocess orchestration + logging
├── templates/
│   └── index.html        # the single-page web UI (HTML + CSS + JS)
├── native/
│   ├── bufferdemo.c      # the vulnerable + safe C program
│   └── Makefile          # compiles two binaries: vulnerable and hardened
├── .dockerignore         # files Docker should not copy into the image
└── README.md             # this document
```

**Dockerfile** — instructions Docker follows to build a self-contained image. It
starts from a small Python image, installs `build-essential` (gcc, make, and the C
headers), installs Flask, copies the project in, compiles the two C binaries with
`make`, and finally starts the Flask app. `ENV PYTHONUNBUFFERED=1` makes log lines
appear immediately in `docker logs`.

**requirements.txt** — lists Python packages to install. Here it is just `Flask`.

**app.py** — the heart of the web tier. It:
- defines the web routes (the four scenario endpoints plus `/api/backend-logs` and
  `/api/verify`);
- runs the chosen C binary as a subprocess with a timeout, and **isolates crashes**
  so the server survives;
- translates the subprocess result (exit code / signal / output) into a clear
  outcome: `crashed`, `corrupted`, `prevented`, `rejected`, or `ok`;
- logs every invocation to the console, to `demo.log`, and to an in-memory buffer
  that the web UI reads — this is the backend evidence trail.

**templates/index.html** — the browser UI: the input box, the four scenario
buttons, the result panel, and the "Backend evidence" section (a live log panel
and a "Verify protections" button). All styling and JavaScript are inline so the
page is a single file.

**native/bufferdemo.c** — the actual C program containing the deliberate
vulnerability and its safe counterparts (explained in detail in section 5).

**native/Makefile** — builds the program twice from the same source: once with
protections OFF (`bufferdemo_vuln`) and once with protections ON
(`bufferdemo_hardened`). See section 6.

**.dockerignore** — tells Docker not to copy compiled binaries or Python caches
into the image (they are rebuilt inside the container).

---

## 5. The C program explained (`native/bufferdemo.c`)

The program takes two command-line arguments: a **mode** and an **input string**,
and dispatches to one of four functions.

- **`run_unsafe` (mode `unsafe`)** — declares `char buffer[64]` and calls
  `strcpy(buffer, input)`. `strcpy` performs **no bounds check**, so input longer
  than 63 characters overruns the buffer, corrupts the stack, and the process
  crashes on return. *This is the vulnerability (scenario ①).*

- **`run_safe` (mode `safe`)** — first checks `strlen(input) >= 64` and **refuses**
  oversized input (like an HTTP 400). Otherwise it uses `snprintf`, which is a
  **bounded** copy that can never write past the buffer. *This is the fix
  (scenario ③).*

- **`run_flag_unsafe` (mode `flag-unsafe`)** — uses a `struct { char buf[16];
  volatile int authorized; }`. Because struct members are laid out in order, an
  overflow of `buf` writes into `authorized`. With an input of 17–24 bytes you can
  see `authorized` change from 0 to a non-zero value, printed as an "INTEGRITY
  VIOLATION". *This demonstrates memory corruption (scenario ②).* (Larger inputs
  overrun further and crash instead, which is why the demo uses 20 bytes here.)

- **`run_flag_safe` (mode `flag-safe`)** — the bounded version of the above; the
  neighbour stays intact.

The program prints a result to stdout/stderr and returns an exit code. If the
overflow corrupts the stack, the **operating system** kills the process with a
signal before it can return normally — and that signal is the proof the bug is
real (section 10).

---

## 6. The compiler flags explained (`native/Makefile`)

The Makefile builds the **same source file** twice with opposite security flags.

**Vulnerable build (`bufferdemo_vuln`):**
```
-O0 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -g
```
- `-fno-stack-protector` — turns OFF the stack canary, so the overflow is not
  detected and reaches the return address (crash).
- `-D_FORTIFY_SOURCE=0` — turns OFF the compiler's safer-libc substitutions.
- `-O0 -g` — no optimization, with debug symbols (clearer for gdb).

**Hardened build (`bufferdemo_hardened`):**
```
-O2 -fstack-protector-all -D_FORTIFY_SOURCE=2 -fPIE -pie -Wall
```
- `-fstack-protector-all` — inserts a **stack canary** (a secret value) before the
  return address in every function and checks it on return; a smash corrupts the
  canary first, which is detected → safe abort.
- `-D_FORTIFY_SOURCE=2` (needs `-O2`) — the compiler replaces unsafe calls like
  `strcpy` with size-checked variants that abort on overflow.
- `-fPIE -pie` — position-independent executable, so the binary participates in
  **ASLR** (randomized load addresses).

The point: **same code, opposite outcome** — silent corruption/crash vs. detected
and safely aborted. Run `make` to build both, `make test` to run all scenarios,
`make clean` to remove the binaries.

---

## 7. Installing Docker

Docker runs the whole demo, so you do **not** need to install gcc, make, Python,
 on your computer — the container provides them.

### Windows 10/11
1. Ensure virtualization is enabled in BIOS (most modern PCs have it on).
2. Install WSL2: open **PowerShell as Administrator** and run `wsl --install`,
   then reboot.
3. Download **Docker Desktop for Windows** from docker.com and install it
   (accept the WSL2 backend option).
4. Launch Docker Desktop and wait until the whale icon in the system tray says
   "Docker Desktop is running".
5. Verify in a terminal: `docker --version`.
---

## 8. Building & deploying

From inside the `buffer-overflow-demo` folder:

```bash
# 1) Build the image (first build downloads the base image; needs internet once).
docker build -t bof-demo .

# 2) Run it. We publish container port 5000 on host port 5001 to avoid clashes.
docker run -d --rm -p 5001:5000 --name bof bof-demo

# 3) Open the app:
#    http://localhost:5001
```

Flags explained: `-d` runs detached (in the background); `--rm` auto-removes the
container when it stops; `-p 5001:5000` maps host:container ports (change the
**left** number if 5001 is busy); `--name bof` gives it a friendly name so you can
reference it in `docker logs` / `docker stop`.

Stop it when done:
```bash
docker stop bof
```

> **Offline use:** after the first successful build, the image is cached locally
> and the demo runs with no internet connection.

---

## 9. How to demonstrate (step by step)

Open `http://localhost:5001` and run the buttons in this order — it tells a story
from "the bug is real and harmful" to "the defences stop it." The result appears
in the result panel; the live log panel below mirrors each action.

1. **Baseline.** Leave input as `hello`, click **③ Prevention — Bounds check →
   SECURE**. Result: `OK`. "Normal input works fine."
2. **Crash (availability).** Click preset **overflow 64-byte buf (200)**, then
   **① Exploitation — Crash → VULNERABLE**. Result: `CRASHED · SIGSEGV`. "200 bytes
   overran a 64-byte buffer; the return address was corrupted; the process died."
3. **Corruption (integrity).** Click preset **overflow 16-byte buf (20)**, then
   **② Exploitation — Corruption → VULNERABLE**. Result: `CORRUPTED` with
   `authorized` overwritten. "The overflow crossed a boundary and changed a
   neighbouring variable."
4. **Prevention by code.** Click preset **overflow 64-byte buf (200)**, then
   **③ Prevention — Bounds check → SECURE**. Result: `REJECTED`. "Length is
   validated first; no overflow occurs."
5. **Prevention by compiler.** Keep 200, click **④ Prevention — Compiler hardening
   → HARDENED**. Result: `PREVENTED · *** buffer overflow detected ***`. "Same
   unsafe code, but the stack canary catches the overflow and aborts safely."

Closing line: *"The bug is real and causes crashes and corruption; it is stopped
at two layers — the code and the compiler — and memory-safe languages remove it
entirely."*

---

## 10. Proving it is real (backend evidence)

The outcomes are produced by the **operating system**, not invented by the web
app. Three proofs, all visible in the browser:

- **Exit codes / signals.** Each result shows the exit code and signal. A crash is
  `SIGSEGV` (`139` at the shell = 128 + 11); the hardened abort is `SIGABRT`
  (`134` = 128 + 6) plus the glibc message `*** buffer overflow detected ***`. The
  kernel and the C runtime emit these; Python only reports them.
- **Live backend log panel.** Updates the moment you click. Each browser action
  produces matching `INVOKE` / `RESULT` / `STDERR` lines with the binary name,
  input length, exit code, and signal.
- **"Verify protections" button.** Runs `objdump`/`readelf` on the two binaries on
  the backend and shows, in the page, that the hardened binary contains the
  stack-canary check (multiple `__stack_chk_fail` references) and the vulnerable
  one has none — with different SHA-256 hashes proving they are different machine
  code from the same source. This proves scenario ④ is a genuine compiler
  difference, not a hardcoded message.

*(Optional, advanced.)* Inside the container you can `apt-get install -y gdb` and
run the vulnerable binary under gdb to observe the SIGSEGV and the corrupted
instruction pointer (`RIP = 0x4141...`) — forensic observation of *why* it
crashed, not exploitation.

---

## 11. Viewing logs in the container

Every request is logged to the console, to `/app/demo.log`, and to the in-UI
panel. To see them from Docker:

```bash
# Live stream (run the container with --name as in section 8):
docker logs -f bof

# One-off dump:
docker logs bof

# Read the log file inside the container:
docker exec bof cat /app/demo.log

# Copy the log file out for your report appendix:
docker cp bof:/app/demo.log .
```

A nice presentation setup: browser on one side, `docker logs -f bof` on the other,
so each click produces a backend log line in real time.

---

## 12. Prevention techniques

- **Bounds checking (code).** Validate length, then use a bounded copy
  (`snprintf`, `strncpy`, `fgets`). The most important habit; it is the
  application-level fix (scenario ③).
- **Stack canary + FORTIFY_SOURCE (compiler).** A secret value before the return
  address is checked on return; FORTIFY swaps unsafe libc calls for checked ones.
  Overflow is detected and the process aborts safely (scenario ④).
- **ASLR.** OS randomizes memory layout each run so attackers cannot rely on fixed
  addresses. The hardened binary is built `-fPIE -pie` to participate.
- **DEP / NX.** Data pages (stack/heap) are non-executable, so injected data cannot
  run as code. Verify: `readelf -l <binary> | grep GNU_STACK` should show `RW`.
- **Memory-safe languages.** Java, C#, Python, Go, Rust prevent the bug by design.
  This is why the companion Java lab in the larger project cannot overflow.

---

## 13. Ties to real-world attacks

The same "unbounded copy into a fixed buffer" pattern caused major incidents:
- **Morris Worm (1988)** — overflow in the Unix `fingerd` daemon (`gets()` into a
  fixed stack buffer); nearly identical to scenario ①.
- **Code Red (2001)** — overflow in Microsoft IIS; infected hundreds of thousands
  of servers.
- **SQL Slammer (2003)** — overflow in Microsoft SQL Server; saturated networks
  worldwide within minutes (massive availability impact, like scenario ①).
- **Heartbleed (2014)** — a *related but different* bug: a missing-bounds-check
  over-**read** in OpenSSL (leaked memory) rather than an over-write.

The defences in this demo (stack canaries, FORTIFY, ASLR/NX, memory-safe
languages) are the industry's response to exactly these attacks. *Verify specific
figures against primary sources (CERT advisories) before quoting them in a report.*

---

## 14. Troubleshooting

**`'make' is not recognized` (Windows).** You ran `make` directly on Windows,
which has no `make`/`gcc`. Use Docker instead (section 8); the build runs `make`
*inside* the container.

**`fatal error: stdio.h: No such file or directory` during build.** The C headers
were missing. The Dockerfile installs `build-essential` (which bundles gcc, make,
and the headers); make sure your Dockerfile's apt line says `build-essential`, then
`docker build` again.

**`Bind for 0.0.0.0:5000 failed: port is already allocated`.** Another process is
using that host port. Map a different one: `docker run -d --rm -p 5001:5000 --name
bof bof-demo` and open `http://localhost:5001`. To find the culprit on Windows:
`netstat -ano | findstr :5000`.

**`Cannot connect to the Docker daemon`.** Docker Desktop is not running — start it
and wait for the "running" status, then retry.

**Code changes not taking effect.** Docker caches the old image. Rebuild with
`docker build -t bof-demo .` before running again.

---
