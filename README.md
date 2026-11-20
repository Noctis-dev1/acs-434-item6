# acs-434-item6

Evidence for item 6 of [ACS #434](https://github.com/GenAI-Security-Project/agent-control-standard/issues/434), "Malformed Guardian responses at a host". It covers Claude Code 2.1.322 with the reference `claude_code` adapter, six malformed Guardian answers at `steps/toolCallRequest`, and three campaigns of 140 runs each.

**Start with [REPORT.md](REPORT.md):** the findings, pinned versions, results table and what stayed untested.

| Path | What it is |
|---|---|
| `REPORT.md` | The report, in the shape of PR #113 |
| `fault_guardian.py` | The Guardian that answers correctly except at the gate, where it misbehaves one way per run |
| `stub_model.py` | The stub model behind `ANTHROPIC_BASE_URL`: one `Write` call per turn |
| `run_item6.py` | The campaign runner. It records raw evidence and scores nothing |
| `verify.py` | The verifier: re-derives every result without importing the runner, Guardian or adapter (checks C1 to C7; `--selftest` plants seven tampers) |
| `check_delivery.py` | Fault-delivery checks that C1 leaves out |
| `evidence/` | One `evidence.json` per run, for each of the three campaigns |
| `results/` | Per-campaign summaries |

Check the stored evidence without re-running anything:

```bash
.venv/bin/python verify.py evidence/campaign-2026-11-20-head
.venv/bin/python check_delivery.py evidence/campaign-2026-11-20-head
```

Setup and a full re-run are under "Reproduce" in REPORT.md.

## License

Apache-2.0 (see [LICENSE](LICENSE)), matching the upstream ACS project. Copyright © 2026 Malachi Zion Kopman.
