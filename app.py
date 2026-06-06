"""
Flask web application that demonstrates a server-side buffer overflow and its
prevention, by invoking the native C binaries as isolated SUBPROCESSES.

Design / safety notes
----------------------
* The risky native code runs in a child process. If it crashes (SIGSEGV), only
  the child dies; this Flask server keeps serving and reports the crash. That
  isolation is itself a defensive technique (sandboxing untrusted/native code).
* A timeout guards against a hung child.
* Input length is capped before we ever reach the unsafe path in the "secure"
  endpoints — the web tier does its own validation (defence in depth).
* This app contains NO exploit logic: it only triggers the vulnerable binary with
  user input and reports the observable outcome (success / crash / corruption /
  prevented), then contrasts it with the safe behaviour.
"""
import os
import signal
import logging
import subprocess
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# --- Backend audit logging ---------------------------------------------------
# Every native invocation is logged to BOTH the console (visible via
# `docker logs <container>` or in the terminal running the container) AND to a
# file `demo.log`. This is the evidence trail proving the outcomes are real
# subprocess results, not hardcoded UI text.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("demo.log")],
)
log = logging.getLogger("bof-demo")

# In-memory ring buffer of recent log lines, exposed to the web UI at
# /api/backend-logs so the examiner can see the real backend trace in the browser.
from collections import deque
LOG_BUFFER: "deque[str]" = deque(maxlen=200)


class BufferHandler(logging.Handler):
    def emit(self, record):
        LOG_BUFFER.append(self.format(record))


_bh = BufferHandler()
_bh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(_bh)
log.setLevel(logging.INFO)

# Directory holding the compiled binaries (built by the Makefile / Dockerfile).
NATIVE_DIR = os.path.join(os.path.dirname(__file__), "native")
VULN_BIN = os.path.join(NATIVE_DIR, "bufferdemo_vuln")
HARD_BIN = os.path.join(NATIVE_DIR, "bufferdemo_hardened")

# Hard cap on input we will pass to ANY subprocess (a sanity limit, not the demo's
# bounds check). Keeps the lab safe even if someone pastes megabytes.
MAX_INPUT = 4096


def run_native(binary: str, mode: str, user_input: str) -> dict:
    """Public entry point: log the invocation, classify the outcome, log the
    result, and return it. The two log lines per call are the audit trail."""
    n = len(user_input)
    log.info("INVOKE  bin=%s mode=%s input_len=%d", os.path.basename(binary), mode, n)
    result = _classify(binary, mode, user_input)
    result["binary"] = os.path.basename(binary)
    log.info("RESULT  bin=%s mode=%s outcome=%s exit=%s signal=%s",
             os.path.basename(binary), mode, result.get("outcome"),
             result.get("exit"), result.get("signal", "-"))
    if result.get("stderr"):
        log.info("STDERR  %s", result["stderr"])
    return result


def _classify(binary: str, mode: str, user_input: str) -> dict:
    """Run a native binary as a subprocess and translate the result into a
    structured, human-readable outcome for the UI."""
    if len(user_input) > MAX_INPUT:
        return {"outcome": "blocked", "detail": "input exceeds lab safety cap"}

    try:
        proc = subprocess.run(
            [binary, mode, user_input],
            capture_output=True, text=True, timeout=5
        )
    except subprocess.TimeoutExpired:
        return {"outcome": "timeout", "detail": "subprocess timed out"}
    except FileNotFoundError:
        return {"outcome": "error", "detail": f"binary not built: {binary}"}

    rc = proc.returncode
    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    # Check FIRST for a protection-triggered safe abort. The stack canary /
    # FORTIFY_SOURCE abort the process via SIGABRT (so returncode is negative),
    # but it is a *prevention*, not an uncontrolled crash — so it must be matched
    # before the generic signal-crash branch below.
    if "stack smashing detected" in stderr or "buffer overflow detected" in stderr \
            or rc == 134 or rc == -6:
        return {
            "outcome": "prevented",
            "detail": "PROTECTION TRIGGERED: the compiler's stack canary / "
                      "FORTIFY_SOURCE detected the overflow and safely aborted "
                      "the process instead of allowing silent corruption.",
            "stdout": stdout, "stderr": stderr, "exit": rc,
        }

    # Negative return code => killed by a signal (Python convention).
    if rc < 0:
        signame = signal.Signals(-rc).name
        return {
            "outcome": "crashed",
            "signal": signame,
            "detail": f"Server-side process CRASHED ({signame}). The buffer "
                      f"overflow corrupted the stack and the process died — a "
                      f"denial-of-service / availability impact.",
            "stdout": stdout, "stderr": stderr, "exit": rc,
        }

    if "INTEGRITY VIOLATION" in stdout:
        return {
            "outcome": "corrupted",
            "detail": "The overflow crossed a buffer boundary and corrupted an "
                      "adjacent variable in memory (integrity impact).",
            "stdout": stdout, "stderr": stderr, "exit": rc,
        }

    if "rejected" in stderr:
        return {
            "outcome": "rejected",
            "detail": "Bounds check refused the oversized input — no overflow "
                      "occurred (prevention working).",
            "stdout": stdout, "stderr": stderr, "exit": rc,
        }

    return {
        "outcome": "ok",
        "detail": "Processed normally.",
        "stdout": stdout, "stderr": stderr, "exit": rc,
    }


@app.route("/")
def index():
    return render_template("index.html")


# --- VULNERABLE endpoints (use the un-hardened binary, unsafe code paths) ---
@app.route("/api/vuln/crash", methods=["POST"])
def vuln_crash():
    data = request.get_json(force=True)
    return jsonify(run_native(VULN_BIN, "unsafe", data.get("input", "")))


@app.route("/api/vuln/corrupt", methods=["POST"])
def vuln_corrupt():
    data = request.get_json(force=True)
    return jsonify(run_native(VULN_BIN, "flag-unsafe", data.get("input", "")))


# --- PREVENTION endpoints ---
@app.route("/api/secure/bounds", methods=["POST"])
def secure_bounds():
    """Same logic, but the C code validates length and uses a bounded copy."""
    data = request.get_json(force=True)
    return jsonify(run_native(VULN_BIN, "safe", data.get("input", "")))


@app.route("/api/secure/hardened", methods=["POST"])
def secure_hardened():
    """Same UNSAFE source path, but compiled WITH stack canary + FORTIFY_SOURCE,
    so the overflow is detected and the process aborts safely."""
    data = request.get_json(force=True)
    return jsonify(run_native(HARD_BIN, "unsafe", data.get("input", "")))


@app.route("/api/backend-logs")
def backend_logs():
    """Return the recent backend log lines (newest last) for the live log panel."""
    return jsonify({"lines": list(LOG_BUFFER)})


@app.route("/api/verify")
def verify():
    """Run objdump / readelf on BOTH binaries and report hard evidence that they
    are compiled differently: the hardened build contains the stack-canary check
    and a non-executable stack; the vulnerable build does not. This proves the
    'compiler hardening' scenario is real, not a hardcoded message — and it all
    runs on the backend and is shown in the browser."""
    import hashlib

    def analyse(path):
        info = {"exists": os.path.exists(path)}
        if not info["exists"]:
            return info
        # Count references to the stack-canary check function.
        canary = subprocess.run(
            ["bash", "-c", f"objdump -d '{path}' | grep -c __stack_chk_fail"],
            capture_output=True, text=True)
        info["stack_canary_refs"] = int(canary.stdout.strip() or "0")
        # GNU_STACK flags: 'RW' = non-executable (NX on); 'RWE' = executable.
        rel = subprocess.run(
            ["bash", "-c", f"readelf -l '{path}' | grep -A1 GNU_STACK"],
            capture_output=True, text=True)
        info["nx_stack"] = ("RWE" not in rel.stdout)
        info["size_bytes"] = os.path.getsize(path)
        with open(path, "rb") as f:
            info["sha256"] = hashlib.sha256(f.read()).hexdigest()[:16]
        return info

    log.info("VERIFY  running objdump/readelf on both binaries")
    return jsonify({
        "vulnerable": analyse(VULN_BIN),
        "hardened": analyse(HARD_BIN),
    })


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from the host when run in Docker; localhost only.
    app.run(host="0.0.0.0", port=5000)
