# Examples

| Example | Policy | Cases | Shows |
|---|---|---|---|
| [`consent-share/`](consent-share/) | Consent-based document sharing (the paper's pilot rule) | 10 explicit matched pairs from the pilot (`export_from_pilot.py`) | **Acceptance test:** `views.json` reproduces the pilot's `results/summary.csv` and `family_breakdown.csv` byte for byte. `views_extended.json` adds common redaction choices; results are in `results/declared/` and `results/undeclared/`. |
| [`accounts-payable/`](accounts-payable/) | A payment agent executing supplier payments: 12 conditions, three event types, all five needs, four-eyes as `relation: different`, amounts as a private category | 5 authorised bases → 60 generated boundary violations | Nine views, including the log vendor's default mask, the current and proposed production exports, ranked amounts, declared IBAN last-4, and an in-house regex redactor (`exec`) that is UNSAFE and leaks 44/81 values. `prod_proposed_amounts_ranked` verifies every condition in both readings with 0/81 exposure. Results are in `results/`. |
| [`../redaction_audit/template/`](../redaction_audit/template/) | A support agent reading a customer record, from trace-shaped (span) logs | 6 authorised bases → 36 generated boundary violations | The starter audit copied by `python3 -m redaction_audit init`. Includes all five evidence needs, an external redactor (`exec`), a reviewer template and a CI gate. |

Reproduce the consent-share results:

```bash
E=examples/consent-share
python3 -m redaction_audit run --policy $E/policy.json --fields $E/fields.json --cases $E/cases.jsonl \
  --views $E/views_extended.json --out $E/results/declared
python3 -m redaction_audit run --policy $E/policy.json --fields $E/fields.json --cases $E/cases.jsonl \
  --views $E/views_extended.json --reviewer undeclared --out $E/results/undeclared
```
