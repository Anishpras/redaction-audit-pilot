# What Evidence Do AI Agent Audit Logs Need After Redaction?

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24163831.svg)](https://doi.org/10.5281/zenodo.24163831)

Action logs, such as those of AI agents, are redacted before people review them, yet the reviewer still has to decide whether each action was authorised. **This repository lets you test whether your redaction keeps that possible, and what it still exposes.** It also contains the matched-pair study that motivated it.

- **Paper:** [`paper/main.pdf`](paper/main.pdf)
- **Use it on your own logs:** [`docs/tutorial.md`](docs/tutorial.md), with every key in [`docs/reference.md`](docs/reference.md)
- **The idea in one page:** [`docs/evidence-needs.md`](docs/evidence-needs.md)

Everything uses only the Python standard library (3.9+), with no network or paid services. All data in the repository is synthetic and fictional.

## Use it on your own logs

```bash
git clone https://github.com/Anishpras/redaction-audit-pilot && cd redaction-audit-pilot
python3 -m redaction_audit init my-audit        # a working starter audit to copy and edit
python3 -m redaction_audit run --policy my-audit/policy.json --fields my-audit/fields.json \
  --cases my-audit/cases.jsonl --views my-audit/views.json --out my-audit/out
```

You describe four things as files:

| File | What it holds |
|---|---|
| `policy.json` | Your rule, as conditions that each declare an *evidence need*: equality, order, explicit state, raw value or presence |
| `fields.json` | Your private fields and time fields |
| `cases.jsonl` | 5–20 authorised example logs. The tool **generates** one matched violation per condition, at the boundary. |
| `views.json` | The redaction schemes to compare, including your own redactor as a command |

You get back:

- **`matrix.md`:** for each condition and redaction scheme, one of four statuses:
  - **verified**;
  - **unverifiable** (the evidence is gone);
  - **UNSAFE** (the reviewer is misled into wrong verdicts);
  - **untested** (no case violates the condition).
- **`evidence_requirements.md`:** a generated checklist of what your logs must keep.
- **Direct exposure** of private values, and the exact bytes each reviewer call saw.
- **An exit code for CI gating:** `--fail-on unsafe,unverifiable --gate production`.

To test a model or human-in-the-loop reviewer instead of the built-in rule reviewer, plug it in with `--reviewer exec:<command>`.

**Examples:**

| Example | What it is |
|---|---|
| [`examples/accounts-payable/`](examples/accounts-payable/) | A payment agent with 12 conditions, including four-eyes, amounts and IBAN checks, and a realistic in-house redactor. It finds a design that verifies every condition with zero private values visible. |
| [`redaction_audit/template/`](redaction_audit/template/) | The starter audit: a support agent reading customer records, from trace-shaped logs |
| [`examples/consent-share/`](examples/consent-share/) | The paper's pilot, as toolkit input |

**More documentation:**

- [`docs/standards-mapping.md`](docs/standards-mapping.md): how this lines up with OpenTelemetry GenAI traces, OCSF, ISO/IEC TS 27560 consent records (through W3C DPV), PROV-O and the Presidio redactor.
- [`spec/`](spec/): JSON Schemas for the input files.

## What we found

This is the pilot: 20 matched runs of a document-sharing agent under a consent rule.

| How the log is redacted | Identical pairs | Reviewer correct | Allowed shares confirmed | Private values visible |
|---|---|---|---|---|
| Full log | 0/10 | 20/20 | 10/10 | 66/66 |
| Uniform masks | **6/10** | 4/20 | **0/10** | 0/66 |
| Consistent per-run aliases | 0/10 | **20/20** | 10/10 | **0/66** |
| Aliases, expiry dropped | 2/10 | 8/20 | 0/10 | 0/66 |
| Aliases, revocation dropped | 2/10 | 8/20 | 0/10 | 0/66 |

The exploratory follow-up ran common redaction choices and two reviewer types: one that knows how the log was redacted (declared) and one that doesn't (undeclared). Full results are in [`examples/consent-share/results/`](examples/consent-share/results/).

| Redaction choice | Declared reviewer | Undeclared reviewer |
|---|---|---|
| Type labels, a common redactor default | unverifiable | **UNSAFE:** approves 6/10 violations |
| Hash with a random salt per event | unverifiable | **UNSAFE:** flags 10/10 authorised actions |
| Times rounded to 10 units | unverifiable at boundaries | **UNSAFE:** 2 false alarms |
| Keyed hash per run, or global | verified | verified |
| Times replaced by their order within the run | verified | verified |

In short:

- Keep **who and which consistent within the run** (identity equality, without the identities).
- Keep the **order** of times.
- Record authority **state explicitly**.
- **Declare** how the log was redacted.

The paper explains which results are by construction and which are not.

## Reproduce the paper's pilot

```bash
python3 run_pilot.py      # about 7 s; exit 0 only if all 91 checks pass
```

- **What it runs:** it rebuilds every number in the paper from hand-specified fixtures. Each call to the isolated reviewer gets a fresh empty directory and its input on stdin only.
- **Pre-specification:** the protocol, data and code are checked against `FREEZE.json`, a self-attested freeze made before the main run.
- **Toolkit cross-check:** the toolkit independently reproduces the pilot's `results/summary.csv` and `family_breakdown.csv` byte for byte, through `examples/consent-share/views.json` and the test suite.

Tests:

```bash
python3 -m unittest discover -s tests -t .           # pilot (30 tests)
python3 -m unittest discover -s tests_toolkit -t .   # toolkit (29 tests)
```

## Layout

| Path | Contents |
|---|---|
| `redaction_audit/` | The reusable toolkit (`python3 -m redaction_audit`) and its starter template |
| `docs/` | Tutorial, full reference, evidence-needs vocabulary, standards mapping |
| `spec/` | JSON Schemas for `policy.json` and `views.json` (including redaction declarations) |
| `examples/` | The pilot expressed as toolkit input (acceptance test) and exploratory results |
| `paper/` | The technical report (LaTeX source and PDF) |
| `PROTOCOL.md`, `FREEZE.json` | Pilot protocol, pre-specified hypotheses, revision log, hash history |
| `run_pilot.py`, `pilot/`, `tests/`, `data/`, `results/` | The frozen pilot study and its outputs |
| `tests_toolkit/` | Toolkit tests |
| `.github/workflows/ci.yml` | CI on Linux and macOS, Python 3.9–3.13 |

## Citation and licence

Archived on Zenodo: **https://doi.org/10.5281/zenodo.24163831** (all versions; this always resolves to the latest). Version 1.2.0 specifically: https://doi.org/10.5281/zenodo.24163832. Citation metadata is in `CITATION.cff`; GitHub's "Cite this repository" button uses it.

> Prashun, A. (2026). *What Evidence Do AI Agent Audit Logs Need After Redaction? A matched-pair pilot and a reusable toolkit for auditable redaction* (Version 1.2) [Software and technical report]. Zenodo. https://doi.org/10.5281/zenodo.24163831

- **Code:** MIT (`LICENSE`).
- **Paper, protocol, fixtures and results:** CC BY 4.0 (`LICENSE-DATA.md`).

This work was prepared with substantial AI assistance; see the paper's acknowledgements.
