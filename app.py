"""
Flask web application that demonstrates a server-side buffer overflow and its
prevention, by invoking the native C binaries as isolated SUBPROCESSES.
"""
import os
import signal
import logging
import subprocess
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

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


def _parse_memory(stdout: str):
    """Turn the C program's key=value evidence lines into a structured dict, and
    decode the corrupted neighbour bytes back into characters. Returns None if the
    output is not from a flag-mode run."""
    if "verdict=" not in stdout:
        return None
    d = {}
    for line in stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            d[k.strip()] = v.strip()
    # Decode authorized_after (a 32-bit int) into its 4 bytes, little-endian, so
    # the characters appear in the same order they were typed.
    try:
        after = int(d.get("authorized_after", "0"), 16)
        raw = after.to_bytes(4, "little")
        d["neighbour_chars"] = "".join(chr(x) if 32 <= x < 127 else "." for x in raw)
    except Exception:
        d["neighbour_chars"] = ""
    # How many bytes spilled past the 16-byte buffer.
    try:
        d["bytes_past_buffer"] = max(
            0, int(d.get("input_len", "0")) - int(d.get("buffer_size", "16")))
    except Exception:
        d["bytes_past_buffer"] = 0
    return d


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

    # Flag modes emit key=value evidence lines (addresses, before/after value).
    # Parse them into a structured 'memory' object the UI renders as proof.
    mem = _parse_memory(stdout)
    if mem is not None:
        # Authorization scenario: an 'access' field is present.
        if "access" in mem:
            granted = mem.get("access") == "GRANTED"
            if granted:
                detail = (f"PRIVILEGE ESCALATION: the overflow flipped the "
                          f"'is_admin' guard from 0x00000000 to "
                          f"{mem.get('authorized_after')}, so the server treated "
                          f"an ordinary request as ADMIN. A memory bug became an "
                          f"access-control bypass — the attacker gained control "
                          f"they were never granted.")
            else:
                detail = ("Access correctly DENIED: the input fit the buffer, so "
                          "the 'is_admin' guard stayed 0x00000000.")
            return {
                "outcome": "escalated" if granted else "ok",
                "detail": detail,
                "access": mem.get("access"),
                "memory": mem,
                "stdout": stdout, "stderr": stderr, "exit": rc,
            }
        corrupted = mem.get("verdict") == "CORRUPTED"
        if corrupted:
            detail = (f"INTEGRITY VIOLATION: the overflow wrote "
                      f"{mem['bytes_past_buffer']} byte(s) past the 16-byte buffer "
                      f"into the adjacent 'authorized' variable, changing it from "
                      f"0x00000000 to {mem.get('authorized_after')} "
                      f"(those bytes decode to '{mem['neighbour_chars']}' — your "
                      f"input literally spilled into the neighbour).")
        else:
            detail = ("No corruption: the input fit within the 16-byte buffer, so "
                      "the adjacent 'authorized' variable stayed 0x00000000.")
        return {
            "outcome": "corrupted" if corrupted else "ok",
            "detail": detail,
            "memory": mem,
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


@app.route("/api/vuln/auth", methods=["POST"])
def vuln_auth():
    """Authorization-bypass demo: overflow flips an adjacent is_admin guard."""
    data = request.get_json(force=True)
    return jsonify(run_native(VULN_BIN, "auth-unsafe", data.get("input", "")))


@app.route("/api/secure/auth", methods=["POST"])
def secure_auth():
    """Same guard, bounded copy: the is_admin flag stays 0, access stays denied."""
    data = request.get_json(force=True)
    return jsonify(run_native(VULN_BIN, "auth-safe", data.get("input", "")))


@app.route("/api/secure/corrupt-safe", methods=["POST"])
def secure_corrupt_safe():
    """Same struct layout as scenario 2 (buffer + adjacent 'authorized'), but a
    bounded copy is used, so the neighbour stays intact. This is the direct
    contrast to /api/vuln/corrupt and emits the same memory-evidence fields."""
    data = request.get_json(force=True)
    return jsonify(run_native(VULN_BIN, "flag-safe", data.get("input", "")))


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from the host when run in Docker; localhost only.
    app.run(host="0.0.0.0", port=5000)
