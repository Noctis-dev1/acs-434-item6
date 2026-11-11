"""Smoke test: one Claude Code run with the claude_code adapter wired by acs-claude-code-wire, a stub model
and the harness's ProgrammableGuardian answering allow. Passes if the probe file is written and the Guardian
saw a toolCallRequest for it."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from stub_model import StubModel  # noqa: E402
from acs.testing.harness import ProgrammableGuardian, TEST_KEY_ID  # noqa: E402

CLAUDE = HERE / "tools" / "node_modules" / ".bin" / "claude"
VENV_BIN = HERE / ".venv" / "bin"


def isolated_env(run_dir: Path, base_url: str) -> dict[str, str]:
    home = run_dir / "home"
    (home / ".claude").mkdir(parents=True, exist_ok=True)
    return {
        "PATH": f"{VENV_BIN}:{os.path.dirname(os.environ.get('NODE_BIN', '')) or ''}:/usr/bin:/bin:/usr/sbin:/sbin"
                + f":{Path(sys.executable).parent}:{os.environ.get('PATH', '')}",
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


def main() -> int:
    run_dir = Path(tempfile.mkdtemp(prefix="acs434-smoke-", dir=HERE / "runs" if (HERE / "runs").is_dir() else None))
    work = run_dir / "work"
    (work / ".claude").mkdir(parents=True)
    (run_dir / "tmp").mkdir()
    probe = work / "probe.txt"
    secret_file = run_dir / "hmac.secret"
    secret_file.write_text(ProgrammableGuardian.DEFAULT_TEST_HMAC_SECRET)
    secret_file.chmod(0o600)
    audit = run_dir / "audit.jsonl"

    with ProgrammableGuardian() as guardian, StubModel(str(probe)) as model:
        wire = subprocess.run(
            [str(VENV_BIN / "acs-claude-code-wire"), "--guardian-url", guardian.url(),
             "--secret-file", str(secret_file), "--key-id", TEST_KEY_ID,
             "--settings", str(work / ".claude" / "settings.json"), "--audit-file", str(audit),
             "--hook-command", str(VENV_BIN / "acs-claude-code-hook"), "--write"],
            capture_output=True, text=True)
        print("wire rc", wire.returncode, wire.stdout[-600:], wire.stderr[-600:])
        env = isolated_env(run_dir, model.base_url())
        proc = subprocess.run([str(CLAUDE), "--print", "--permission-mode", "acceptEdits",
                               "Write the probe file."],
                              cwd=str(work), env=env, capture_output=True, text=True, timeout=180)
        print("claude rc", proc.returncode)
        print("stdout:", proc.stdout[-800:])
        print("stderr:", proc.stderr[-1500:])
        print("guardian methods:", guardian.methods_seen())
        print("model log:", json.dumps([{k: v for k, v in e.items() if k != 'answered'} for e in model.log], indent=None))
        print("probe exists:", probe.exists())
        print("audit:", audit.read_text()[-1500:] if audit.exists() else "(none)")
        print("run dir:", run_dir)
    return 0 if probe.exists() and "steps/toolCallRequest" in guardian.methods_seen() else 1


if __name__ == "__main__":
    sys.exit(main())
