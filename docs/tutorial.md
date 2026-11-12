# Test your own redaction

This tutorial checks whether **your** redacted action logs still let a reviewer verify **your** authorisation rule, and what private data they expose. You need Python 3.9+ and nothing else: no packages, network or accounts.

**How long it takes:** the starter audit runs in seconds. Adapting it to your own system is the real work. In our usability test (an AI agent acting as a first-time user, auditing a new 12-condition payment policy), the estimate for a person's first attempt was **2.5–4 hours**. Most of that time goes on writing the policy and exporting example logs. Later audits reuse those files.

Every key is listed in [`reference.md`](reference.md). Real logs to copy from are in `examples/accounts-payable/` (a payment agent, 12 conditions, a realistic in-house redactor) and `redaction_audit/template/`.

```bash
git clone https://github.com/Anishpras/redaction-audit-pilot && cd redaction-audit-pilot
python3 -m redaction_audit init my-audit          # copies a working starter audit
python3 -m redaction_audit run --policy my-audit/policy.json --fields my-audit/fields.json \
  --cases my-audit/cases.jsonl --views my-audit/views.json --out my-audit/out
```

Run every command from the repository root, with paths prefixed by `my-audit/` as above. Alternatively, run `pip install .` once and use `redaction-audit` in place of `python3 -m redaction_audit` from any directory.

The starter audit checks an agent reading a customer record. Open `out/matrix.md`: every condition × redaction view is **verified**, **unverifiable**, **UNSAFE** or **untested**. Then adapt each file to your system.

## 1. Export 5–20 authorised logs (10 min) → `cases.jsonl`

Use one line per run, holding the events that matter for one decision:

```json
{"case_id": "base-01", "log": {"events": [ {...grant or assignment...}, {...the action...}, {...other events...} ]}}
```

- Each event is a JSON object in **your own** schema, nested however you like (OpenTelemetry-style `attributes` work).
- Other events (LLM calls, retries) can stay; roles select only the events the rule needs.
- Every base must be **authorised**. The tool checks this, and tells you which condition fails if it isn't.
- You don't write violations. For each base and each condition, the tool generates a matched unauthorised partner that breaks exactly that condition, at the boundary (for example expiry set equal to the action time). It then checks that only that condition fails.
- If you already have labelled pairs, use explicit mode instead: add `"pair_id"`, `"family"` and `"label"` to every line (see `examples/consent-share/cases.jsonl`).

## 2. Write the rule (15 min) → `policy.json`

```json
{
  "name": "...",
  "subject": "call",
  "roles": {
    "assignment": {"where": {"span": "ticket_assignment"}},
    "call": {"where": {"span": "execute_tool", "attributes.tool": "read_customer_record"}}
  },
  "conditions": [
    {"id": "customer_matches", "need": "equality",
     "left": "assignment.attributes.customer_id", "right": "call.attributes.customer_id"},
    {"id": "before_close", "need": "order",
     "left": "call.start_time", "op": "<", "right": "assignment.attributes.closes_at"}
  ]
}
```

- **Roles** pick events by field values. Each role must match exactly one event per run.
- **`subject`** names the audited action. Generated violations change the evidence side where possible, not the action.
- **`order` conditions compare numbers.** Convert ISO timestamps to epoch seconds, and money to numbers or minor units (cents), when you export the logs.
- **Four-eyes rules** (approver ≠ requester) are equality conditions with `"relation": "different"`.
- **Conditions** are all required (a logical AND). Each declares one of five evidence *needs*: `equality`, `order`, `explicit_state`, `raw_value` or `presence`. See [`evidence-needs.md`](evidence-needs.md).
- **`mutate`** on a condition overrides the generated violation, for example to use realistic decoy values from `"decoys"`. Use `mutations` (a list) to generate several violations per condition, such as one at the limit and one far beyond it. A base case can carry its own `"decoys"`, for example a lookalike IBAN with the same last four digits.
- The default violation for an identifier changes its **first** character and keeps the ending. That exposes redaction that keeps the last N characters.
- To see what your rule demands of a log before testing anything, run `python3 -m redaction_audit checklist --policy policy.json`.

## 3. Mark private fields and times (10 min) → `fields.json`

```json
{"private": [{"path": "attributes.customer_id", "category": "identifier", "entity": "customer"},
             {"path": "attributes.customer_name", "category": "name"},
             {"path": "attributes.result_excerpt", "category": "content"}],
 "times": ["start_time", "attributes.closes_at"]}
```

- Paths are relative to an event.
- `category` can be any name: `identifier`, `name` and `content` are conventions, and you can add `amount`, `location` and so on. Categories become selectors in `views.json`.
- `entity` groups identifiers that should share one alias namespace, for example approver and requester are both `employee`.
- The exposure scan looks for every private value verbatim in what the reviewer sees.

## 4. Describe your redaction (10 min) → `views.json`

Keep a few reference views (`full`, `alias_per_run`) and add your production configuration. The built-in ops are:

| Op | Effect |
|---|---|
| `mask` | Replace the value with a type label |
| `alias` | Consistent per-run aliases |
| `pseudonym` | Keyed hash, scope `run`, `event` or `global` |
| `partial` | Keep the last N characters |
| `drop` | Remove the field |
| `bucket` | Coarsen times |
| `rank` | Replace times, or amounts, by their order within the run |
| `exec` | Run your own redactor |

To wrap a real redactor, use `exec`:

```json
{"name": "production", "ops": [{"op": "exec", "command": ["python3", "my_redactor.py"]}]}
```

- Your command reads `{"events": [...]}` on stdin and prints `{"events": [...], "declarations": {...}}`.
- **Declarations** say what was done to each field, for example `{"attributes.customer_id": {"method": "mask"}}`.
- Without them, a reviewer reads `<CUSTOMER>` as a real identifier, and the audit will tell you the view is UNSAFE.
- For production pseudonyms, give `pseudonym` a secret through `"key_env": "MY_KEY_VAR"`. The default key is for demonstrations only.

## 5. Run and read the results (5 min)

```bash
python3 -m redaction_audit run --policy my-audit/policy.json --fields my-audit/fields.json \
  --cases my-audit/cases.jsonl --views my-audit/views.json --out my-audit/out
```

Input mistakes stop the run with every problem listed, including unknown keys, selectors that match nothing, roles that match zero or several events, and non-numeric times. Each problem comes with a "did you mean" hint where possible.

| Output | Use |
|---|---|
| `out/matrix.md` | Which conditions each view keeps verifiable, the same views read without the redaction header, and the case IDs behind every problem |
| `out/exposure.csv` | Which private fields remain visible in each view |
| `out/evidence_requirements.md` | What a redacted log must keep for this rule, and which tested views do |
| `out/summary.csv` | Identical pairs, accuracy ceiling, reviewer outcomes and exposure per view |
| `out/per_case.jsonl`, `out/inputs/` | Every verdict and the exact bytes the reviewer saw |

**Statuses:**

- **verified:** every authorised case was confirmed, and every violation that targets this condition was detected.
- **unverifiable:** the view hides evidence, so some cases cannot be decided. This is honest, but the redacted log can't clear those actions.
- **UNSAFE:** the reviewer reached at least one wrong verdict, because the view changed values in a way it didn't declare. Fix this first.
- **untested:** no case violates the condition, so a wrong "pass" couldn't be caught. Generated mode always tests every condition.

The built-in reviewer also reports, in the second table of `matrix.md` and in `readings.csv`, what a reviewer who doesn't know your redaction scheme would conclude. If a view is fine above but UNSAFE there, it is safe only while its declaration travels with the log.

## 6. Keep it as a CI gate

```bash
python3 -m redaction_audit run ... --fail-on unsafe,unverifiable,unsafe-undeclared,exposed --gate production
```

The exit code is 1 if the production view loses any required evidence, misleads a reviewer (with or without its header) or shows any private value. Run it whenever someone changes the redaction configuration.

## 7. Test your own reviewer (optional)

`--reviewer "exec:python3 my_reviewer.py"` sends `{"policy": ..., "log": ...}` to your command and expects `{"verdict": ..., "checks": {...}}` back. `redaction_audit/template/reviewer_template.py` is a starting point.

Each call runs in an empty temporary directory with a minimal environment; pass the variables your reviewer needs with `--reviewer-env NAME`. Calls are made in a seeded shuffled order.

## Limits to keep in mind

- Each run must contain exactly one event per role, so one authority and one action per run. Split longer traces into one run per audited action.
- The exposure scan checks exact substrings only. Zero means no planted value appears verbatim. It does not mean the log is anonymous: timestamps and structure can still allow linkage.
- The built-in reviewer is a rule evaluator. It shows what the evidence supports, not how well a person or a model uses it.
