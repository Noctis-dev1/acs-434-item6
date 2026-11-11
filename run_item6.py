"""#434 item 6 campaign runner: malformed Guardian responses at a real host.

For each (fault, on_decision_failure, wiring, rep): a fresh run directory, a fresh FaultGuardian, a fresh
stub model, the claude_code adapter wired into project settings by acs-claude-code-wire, and one
`claude --print` turn whose only tool call is a Write of probe.txt. Raw evidence for every run goes to
runs/<campaign>/<config>/rep<N>/evidence.json. This runner scores nothing; verify.py does.

Usage: run_item6.py [--reps N] [--faults a,b] [--postures proceed,deny] [--wirings default,all_fail_open] [--campaign NAME]
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from fault_guardian import FAULTS, FaultGuardian  # noqa: E402
from stub_model import StubModel  # noqa: E402
from acs.testing.harness import ProgrammableGuardian, TEST_KEY_ID  # noqa: E402

CLAUDE = HERE / "tools" / "node_modules" / ".bin" / "claude"
VENV_BIN = HERE / ".venv" / "bin"
ACS_DIR = HERE / "vendor" / "acs"
PROMPT = "Write the probe file."
WIRINGS = {"default": [], "all_fail_open": ["--all-fail-open"]}


def sh(*cmd: str, cwd: Path | None = None) -> str:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True).stdout.strip()


def manifest() -> dict:
    return {
        "acs_commit": sh("git", "rev-parse", "HEAD", cwd=ACS_DIR),
        "acs_dirty": bool(sh("git", "status", "--porcelain", cwd=ACS_DIR)),
        "harness_commit": sh("git", "rev-parse", "HEAD", cwd=HERE),
        "harness_dirty": bool(sh("git", "status", "--porcelain", "--untracked-files=no", cwd=HERE)),
        "claude_code_version": sh(str(CLAUDE), "--version"),
        "python": platform.python_version(),
        "node": sh("node", "--version"),
        "platform": platform.platform(),
        "prompt": PROMPT,
        "faults": list(FAULTS),
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }


def isolated_env(run_dir: Path, base_url: str) -> dict[str, str]:
    home = run_dir / "home"
    (home / ".claude").mkdir(parents=True, exist_ok=True)
    node_dir = str(Path(sh("which", "node")).parent)
    return {
        "PATH": f"{VENV_BIN}:{node_dir}:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home),
        "CLAUDE_CONFIG_DIR": str(home / ".claude"),
        "ANTHROPIC_BASE_URL": base_url,
        # A dummy key: the stub accepts anything, and a real key must never be present in these runs.
        "ANTHROPIC_API_KEY": "sk-ant-dummy-acs434-not-a-real-key",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_TELEMETRY": "1",
        "TMPDIR": str(run_dir / "tmp"),
    }


def read_lines(path: Path) -> list:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(errors="replace").splitlines():
        # The adapter writes each audit record as "ACS_AUDIT <json>" (acs/client/_audit.py).
        body = line[len("ACS_AUDIT "):] if line.startswith("ACS_AUDIT ") else line
        try:
            out.append(json.loads(body))
        except ValueError:
            out.append({"_unparsed": line})
    return out


def one_run(run_dir: Path, *, fault: str, posture: str, wiring: str) -> dict:
    work = run_dir / "work"
    (work / ".claude").mkdir(parents=True)
    (run_dir / "tmp").mkdir()
    probe = work / "probe.txt"
    secret_file = run_dir / "hmac.secret"
    secret_file.write_text(ProgrammableGuardian.DEFAULT_TEST_HMAC_SECRET)
    secret_file.chmod(0o600)
    audit = run_dir / "audit.jsonl"
    settings = work / ".claude" / "settings.json"
    t0 = time.time()
    with FaultGuardian(fault=fault, on_decision_failure=posture) as guardian, StubModel(str(probe)) as model:
        wire_cmd = [str(VENV_BIN / "acs-claude-code-wire"), "--guardian-url", guardian.url(),
                    "--secret-file", str(secret_file), "--key-id", TEST_KEY_ID, "--settings", str(settings),
                    "--audit-file", str(audit), "--hook-command", str(VENV_BIN / "acs-claude-code-hook"),
                    *WIRINGS[wiring], "--write"]
        wire = subprocess.run(wire_cmd, capture_output=True, text=True)
        claude_cmd = [str(CLAUDE), "--print", "--permission-mode", "acceptEdits", PROMPT]
        try:
            proc = subprocess.run(claude_cmd, cwd=str(work), env=isolated_env(run_dir, model.base_url()),
                                  capture_output=True, text=True, timeout=180)
            rc, out, err, timed_out = proc.returncode, proc.stdout, proc.stderr, False
        except subprocess.TimeoutExpired as e:
            rc, out, err, timed_out = None, (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""), "", True
        exchanges = list(guardian.exchanges)
        model_log = list(model.log)
    return {
        "config": {"fault": fault, "on_decision_failure": posture, "wiring": wiring},
        "wire": {"cmd": wire_cmd, "rc": wire.returncode, "stderr_tail": wire.stderr[-2000:]},
        "settings_json": json.loads(settings.read_text()) if settings.exists() else None,
        "claude": {"cmd": claude_cmd, "rc": rc, "timed_out": timed_out, "stdout": out[-4000:], "stderr": err[-4000:]},
        "guardian_exchanges": exchanges,
        "model_log": model_log,
        "audit_events": read_lines(audit),
        "probe": {"exists": probe.exists(),
                  "sha256": hashlib.sha256(probe.read_bytes()).hexdigest() if probe.exists() else None},
        "duration_s": round(time.time() - t0, 2),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--faults", default=",".join(FAULTS))
    ap.add_argument("--postures", default="proceed,deny")
    ap.add_argument("--wirings", default="default,all_fail_open")
    ap.add_argument("--campaign", default=datetime.datetime.now().strftime("campaign-%Y%m%dT%H%M%S"))
    a = ap.parse_args()
    root = HERE / "runs" / a.campaign
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(json.dumps(manifest(), indent=2))
    configs = [(f, p, w) for f in a.faults.split(",") for p in a.postures.split(",") for w in a.wirings.split(",")]
    total = len(configs) * a.reps
    n = 0
    # Reps are the outer loop, so a slow drift in the environment spreads across configurations, not into one.
    for rep in range(1, a.reps + 1):
        for fault, posture, wiring in configs:
            n += 1
            run_dir = root / f"{fault}__{posture}__{wiring}" / f"rep{rep}"
            if (run_dir / "evidence.json").exists():
                continue
            run_dir.mkdir(parents=True, exist_ok=True)
            ev = one_run(run_dir, fault=fault, posture=posture, wiring=wiring)
            ev["config"]["rep"] = rep
            (run_dir / "evidence.json").write_text(json.dumps(ev, indent=1))
            print(f"[{n}/{total}] {fault:17} {posture:8} {wiring:14} rep{rep} "
                  f"probe={ev['probe']['exists']!s:5} rc={ev['claude']['rc']} {ev['duration_s']}s", flush=True)
    (root / "manifest.json").write_text(json.dumps({**json.loads((root / "manifest.json").read_text()),
                                                    "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}, indent=2))
    print("campaign:", root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
