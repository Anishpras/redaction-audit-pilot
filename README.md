# Redaction audit pilot

**What Evidence Do AI Agent Audit Logs Need After Redaction?** This is a small, reproducible pilot. It asks whether a reviewer can still verify consent for an AI agent's completed document share after the audit log has been redacted. It compares three log formats: full logs, uniform masking and consistent within-run aliases.

- **Paper:** [`paper/main.pdf`](paper/main.pdf) (LaTeX source: `paper/main.tex`)
- **Protocol:** [`PROTOCOL.md`](PROTOCOL.md), with pre-registered hypotheses and a revision log

All data is synthetic and fictional. The code is original and uses only the Python 3 standard library. It makes no network calls, uses no model and needs no paid services.

## Key result

| View | Identical pairs | Ceiling | Reviewer correct | Insufficient evidence | Planted values visible |
|---|---|---|---|---|---|
| A. Full log | 0/10 | 20/20 | 20/20 | 0/20 | 66/66 |
| B. Uniform masking | **6/10** | 14/20 | 4/20 | 16/20 | 0/66 |
| C. Consistent aliases | 0/10 | 20/20 | **20/20** | 0/20 | **0/66** |
| C without expiry | 2/10 | 18/20 | 8/20 | 12/20 | 0/66 |
| C without revocation | 2/10 | 18/20 | 8/20 | 12/20 | 0/66 |

Uniform masking collapses every pair whose verdict depends on *who* received *which* document. Under it, the reviewer can confirm none of the 10 authorised shares. Consistent aliases keep the one thing the check needs, whether the grant and the share refer to the same party, and reveal none of the raw values. Dropping expiry or revocation evidence leaves every authorised share unconfirmable.

## Reproduce

```bash
python3 run_pilot.py
```

The command takes about 7 seconds on Python 3.13.7, and the exit code is 0 only if all 91 checks pass. It:

1. checks that `data/` matches `pilot/fixtures.py`, and that every frozen file (protocol, data and all code) matches the latest entry in `FREEZE.json`;
2. runs the pre-run checks: labels against an independent policy oracle, pair construction, boundary cases, planted values, a static allowlist on the reviewer, canonical serialisation, the exposure scanner and 30 unit tests;
3. renders five views of the 20 runs and 5 sanity cases, and passes each exact byte string to `pilot/reviewer.py`. Each call gets a fresh empty temporary directory holding only a copy of the reviewer, runs under `python3 -I` with an empty environment, receives its input on stdin only, and the calls run in a seeded shuffled order;
4. repeats the whole pass in a different order and checks that every input and verdict reproduces;
5. stops if the full-view reviewer disagrees with any label. Otherwise it scores metrics 1–4, checks the metric invariants and runs a supplementary shared-timeline analysis;
6. writes `results/` and prints the summary.

Other commands:

```bash
python3 run_pilot.py --show-pair P01                     # every view's exact input and verdict for one pair
python3 -m unittest discover -s tests -t .               # unit tests only
python3 run_pilot.py --rebuild-fixtures                  # regenerate data/ after an intentional fixture change
python3 run_pilot.py --freeze --freeze-label vX --freeze-note "..."   # record hashes before a run
```

Every result file except `results/run_info.json` (which holds a timestamp) is byte-identical across runs. This was verified across Python 3.12–3.14 and different `PYTHONHASHSEED` values.

## Layout

| Path | Contents |
|---|---|
| `PROTOCOL.md` | Hypotheses and predictions, consent rule, fixtures, private-field decisions, views, metrics, validation and revisions |
| `FREEZE.json` | SHA-256 history: v1.0 (protocol and data, before the main run) and v1.1 (protocol, data and all code) |
| `pilot/fixtures.py` | Hand-specified fixtures (10 pairs, 5 sanity cases, the shared-timeline variant) with hand-written labels and rationales |
| `pilot/policy.py` | Trusted-fact oracle, used only to check the labels |
| `pilot/views.py` | Views A, B and C and the two C ablations; canonical JSON |
| `pilot/reviewer.py` | Standalone three-valued reviewer (imports only `json` and `sys`) |
| `pilot/exposure.py` | Planted-value scanner |
| `pilot/scoring.py` | Metrics 1–4 |
| `pilot/validate.py` | All checks |
| `tests/` | Rule, transformation, isolation and scoring unit tests |
| `data/fixtures.json` | Underlying records: opaque `case_id`, arbitrary `run_id`, events. No labels. |
| `data/manifest.json` | Expected verdicts, rationales, pair IDs, families and sanity expectations |
| `results/summary.csv`, `summary.json` | One row per view, plus full metric detail with denominators and supplementary analyses |
| `results/family_breakdown.csv` | Reviewer metrics by view and case family |
| `results/per_case.csv` | One row per view and case: verdict, outcome, per-condition checks, input hash, exposure |
| `results/inputs/<view>/<case>.json` | The exact bytes each reviewer call received |
| `results/reviewer_outputs.jsonl`, `mixed_label_groups.json`, `sanity.csv`, `validation.json`, `run_info.json` | Raw outputs, mixed-label groups, sanity results, every check and its outcome, and environment, seeds and hashes |
| `paper/` | The technical report (LaTeX source and PDF) |

## Citation and licence

See `CITATION.cff`. The code is released under the MIT License (`LICENSE`). The paper, protocol, fixtures and results are released under CC BY 4.0 (`LICENSE-DATA.md`).

This work was prepared with substantial AI assistance; see the paper's acknowledgements.
