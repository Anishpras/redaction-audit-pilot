# Starter audit: support agent reads a customer record

Copy this folder with `python3 -m redaction_audit init my-audit`, then replace each file with your own.

| File | What it is | What you change |
|---|---|---|
| `policy.json` | The rule, as conditions with an evidence *need* (equality, order, explicit_state, raw_value, presence), plus the roles that pick the relevant events out of a log | Your rule and your event filters |
| `fields.json` | Which fields are private (identifier, name, content) and which are times | Your private and time fields |
| `cases.jsonl` | 5–20 *authorised* example logs, one per line. Unauthorised partners are generated: one per condition, at the boundary. | Exports of your own logs |
| `views.json` | The redaction transforms to compare, including your own command (`exec`) | Your production redaction configuration |
| `my_redactor.py` | Example external redactor | Wrap your real redactor |
| `reviewer_template.py` | Example external reviewer (for example an LLM) | Optional |

Run it:

```bash
python3 -m redaction_audit run --policy policy.json --fields fields.json --cases cases.jsonl \
  --views views.json --out out
```

Read `out/matrix.md` (which conditions each view keeps verifiable) and `out/evidence_requirements.md`. To use the audit as a CI gate for your production view, add `--fail-on unsafe,unverifiable --gate my_redactor`.
