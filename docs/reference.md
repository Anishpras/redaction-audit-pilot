# Reference: input files, options and outputs

This page describes every key the toolkit accepts. Unknown keys are errors, never silently ignored. JSON Schemas for editor support are in [`spec/`](../spec/): `policy.schema.json` and `views.schema.json`.

## `policy.json`

| Key | Required | Meaning |
|---|---|---|
| `name`, `description`, `notes` | no | Text shown in reports |
| `roles` | yes | `{role: {"where": {path: value, ...}}}`. Picks events from each log. A role must match **exactly one** event per log; extra events (LLM calls, retries that failed) can stay. Paths are dotted (`attributes.tool`); keys containing dots are not supported. |
| `subject` | no | The role of the audited action. Generated violations change the evidence side where possible. |
| `conditions` | yes | List of conditions, all of which must hold (a logical AND) |
| `decoys` | no | `{pool: [values]}` or `{pool: value}`: replacement values for mutations. Individual cases can override them. |

Every condition has `id`, `need`, optional `note`, and optional `mutate` (one violation) **or** `mutations` (a list of violations). A role path is `<role>.<event-relative path>`.

| `need` | Keys | Passes when | Notes |
|---|---|---|---|
| `equality` | `left`, `right`, `relation` (`same` by default, or `different`) | the two values are the same, or differ when `relation` is `different` | `different` expresses four-eyes rules (approver ≠ requester) |
| `order` | `left`, `op` (`<`, `<=`, `>`, `>=`), `right` | `left op right` | Values must be **numbers** (integers or decimals). Convert timestamps to epoch seconds, and amounts to numbers or minor units. |
| `explicit_state` | `field`, `pass` (values), `fail` (values), optional `fail_only_if` (an order) | value in `pass`; or value in `fail` while `fail_only_if` is false | Example: status `revoked` counts only if `revocation.effective_at <= action.time` |
| `raw_value` | `field`, `allowed` (values) | value in `allowed` | |
| `presence` | `field` | the field exists | A declared drop makes the condition unknown, not failed |

**Mutations** are a list of steps, each `{"set": {role_path: expression}}` or `{"delete": [role_path, ...]}`. An expression is one of:

- a literal value;
- `{"copy": path}`;
- `{"add": [path, number]}`;
- `{"different_from": path}`, which gives a different value in the same format: the first letter or digit changes and the ending is kept;
- `{"decoy": pool}`;
- `{"literal": value}` (use this to set an object literally).

**Default mutations,** used when you give none, sit on the boundary:

| Need | Default violation |
|---|---|
| `equality` (`same`) | A different value in the same format |
| `equality` (`different`) | The same value copied across |
| `order` | The comparison made false exactly at the boundary: equal values for `<`, an offset of 1 for `<=` |
| `explicit_state` | The first `fail` value, with `fail_only_if` made true at the boundary |
| `raw_value` | A value outside `allowed` |
| `presence` | The field deleted |

Every generated violation must fail **exactly** its condition, or the run stops and asks for an explicit `mutate`. Units: `add` and the boundary offset of 1 are in the field's own units (seconds, cents). Use `mutations` to also test violations further from the limit.

## `fields.json`

| Key | Meaning |
|---|---|
| `private` | `[{"path", "category", "entity"?}]`. `category` is any name you choose (`identifier`, `name`, `content`, `amount`, `location`...); `private` and `times` are reserved. `entity` groups identifiers that share one alias or pseudonym namespace, for example approver and requester are both `employee`. |
| `times` | Event-relative paths of time fields, used by the `times` selector |

Every listed path must appear in at least one case.

## `views.json`

`{"views": [{"name", "role"?, "note"?, "declare"? (default true), "ops": [...]}]}`. Ops run in order.

**`fields` selectors:** `"private"`, `"times"`, any category used in `fields.json`, or an explicit event-relative path. A selector that matches nothing in any case is an error.

| Op | Keys | Effect | Declaration |
|---|---|---|---|
| `keep` | none | Nothing | none |
| `mask` | `fields` | Value becomes `[MASKED:<category>]` | `mask` |
| `alias` | `fields` | First-appearance aliases per run, per entity (`EMPLOYEE_1`) | `alias`, scope `run` |
| `pseudonym` | `fields`, `scope` (`run` / `event` / `global`), `key` or `key_env` | HMAC-SHA256 pseudonyms, salted per run, per event or not at all. Use `key_env` in production. | `pseudonym` + scope |
| `partial` | `fields`, `keep_last`, `fill`? | Keep the last N characters | `partial` + `keep_last` |
| `drop` | `fields`, `where`? | Delete the field (only in events matching `where`) | `drop` |
| `bucket` | `fields`, `size` | Floor numbers to multiples of `size` | `bucket` + size |
| `rank` | `fields`, `group`? | Replace numbers by their dense rank within the run (shared by all fields in the op) | `rank` + group |
| `exec` | `command`, `timeout`? | Run your redactor: stdin `{"events": [...]}`, stdout `{"events": [...], "declarations": {...}?}`. The working directory is the folder of `views.json`. | as returned |

The reviewer receives canonical JSON `{"events": [...], "redaction": {path: declaration}}`. Case IDs never appear in it.

## `cases.jsonl`

One object per line. Base lines and explicit lines can be mixed in one file.

| Line | Keys | What happens |
|---|---|---|
| **Base** | `case_id`, `log: {"events": [...]}`, optional `decoys` | Must be authorised. One violation is generated per condition (or per entry of `mutations`). |
| **Explicit** | `case_id`, `pair_id`, `family`, `label` (`authorised` / `unauthorised`), `log`, optional `target` | Each `pair_id` needs exactly one of each label. The label is checked against the policy. |

## Command line

```bash
python3 -m redaction_audit run --policy P --fields F --cases C --views V [--out DIR]
    [--reviewer builtin | undeclared | exec:"COMMAND"] [--reviewer-env VAR ...]
    [--fail-on unsafe,unverifiable,unsafe-undeclared,exposed] [--gate VIEW[,VIEW]] [--seed N]
python3 -m redaction_audit init DIR
python3 -m redaction_audit checklist --policy P
```

**`--reviewer`:**

- **`builtin`** (default): reads the redaction header, and also reports what a literal reader would conclude (`readings.csv`, second table in `matrix.md`).
- **`undeclared`**: the literal reader only.
- **`exec:`**: your reviewer. It receives `{"policy": ..., "log": ...}` on stdin and returns `{"verdict": ..., "checks"?: {...}}`. Each call runs in an empty temporary directory with only `PATH` plus the variables you pass with `--reviewer-env`, in a seeded shuffled order.

**`--fail-on`**, checked in the `--gate` views (all views if none are given):

| Value | Fails when |
|---|---|
| `unsafe` | A wrong verdict |
| `unverifiable` | A case left undecided |
| `unsafe-undeclared` | A wrong verdict once the redaction header is lost |
| `exposed` | Any private value visible |

Exit codes: 0 = passed, 1 = a `--fail-on` condition occurred, 2 = invalid input (every problem is listed).

## Outputs

| File | Contents |
|---|---|
| `matrix.md`, `matrix.csv` | Status per condition × view; counts; the case and pair IDs behind every problem |
| `readings.csv` | Declared and undeclared status side by side (builtin reviewer) |
| `evidence_requirements.md` | What a log must keep for this policy, and which tested views do |
| `summary.csv`, `summary.json`, `family_breakdown.csv` | Identical pairs, ceiling, reviewer outcomes and exposure per view (the paper's metrics) |
| `exposure.csv` | Visible private values per view and field |
| `per_case.jsonl`, `inputs/<view>/<case>.json` | Every verdict and per-condition result, and the exact reviewer input |
| `run.json` | Tool version, Python, reviewer, seed, SHA-256 of the input files |

**Statuses:**

- **verified:** every authorised case was confirmed and every targeted violation was detected.
- **unverifiable:** some cases are undecided, but none was decided wrongly.
- **unsafe:** at least one wrong verdict.
- **untested:** no case violates this condition (possible only with explicit pairs).
