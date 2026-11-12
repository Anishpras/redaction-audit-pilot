# Evidence needs: a vocabulary for auditable redaction

Every authorisation condition depends on **one kind of evidence**. A redaction scheme is auditable for a rule exactly when it keeps, or honestly declares the loss of, the evidence each condition needs. This is the core idea; the toolkit puts it into practice, and the paper's pilot is one example of it.

## The five needs

| Need | Question it answers | Kept by | Lost by | Dangerous when undeclared |
|---|---|---|---|---|
| `equality` | Do two fields refer to the same thing (same person, same document), or, with `relation: different`, to different things (four-eyes)? | Raw values. Aliases or keyed pseudonyms consistent across the events compared (scope `run` or `global`). | Uniform masks. Per-event pseudonyms. Dropping. | Uniform masks read as equal let every misdirected action through. Per-event pseudonyms read as different flag every authorised action. |
| `order` | Is one number at most another: a time before a deadline, an amount within a limit? | Exact values. Within-run ranks (order and ties kept), which also hide the values. | Dropping. Masking. Coarsening near the boundary. | Coarsened times read as exact give wrong verdicts on boundary cases. |
| `explicit_state` | Was the authority in a given state, for example revoked, closed or suspended, at the time of the action? | The state written explicitly, including the clear state (`not_revoked`), plus its effective time. | Dropping. Recording the clear state only by omission. | A missing field read as "no revocation" clears revoked actions. |
| `raw_value` | Is a value in an allowed set (role, region, data class)? | The value, or a non-identifying category that still answers the question. | Masking. Pseudonymising. | Rare. Usually it is honestly unverifiable. |
| `presence` | Does a required record exist at all (approval, ticket, notice)? | Keeping the field, even with a masked value. | Dropping. | An undeclared drop reads as "absent", which is a violation. |

**How to use the table:** write each condition of your rule down with its need, then check the "Kept by" column against your redaction design. `python3 -m redaction_audit checklist --policy policy.json` generates this as `evidence_requirements.md` for your own policy.

## Declarations

A redacted log should say how it was redacted. The toolkit puts this in a header that travels with the log:

```json
{"events": [...],
 "redaction": {
   "recipient.id": {"method": "pseudonym", "scope": "run"},
   "document.title": {"method": "mask"},
   "time": {"method": "bucket", "size": 60},
   "revocation": {"method": "drop"}}}
```

| `method` | Fields | How the declaration-aware reviewer reads it |
|---|---|---|
| `mask` | none | Value unknown for every need |
| `alias` | `scope: "run"` | Comparable for equality within the run |
| `pseudonym` | `scope: "run"`, `"event"` or `"global"` | Comparable for equality only within the scope. `event` is never comparable across events. |
| `partial` | `keep_last: n` | Different kept endings prove the values differ; equal endings prove nothing |
| `bucket` | `size: n` | A value v stands for [v, v+n). Order is decided only if the intervals cannot overlap. |
| `rank` | `group` | Exact order and equality between fields of the same group |
| `drop` | none | Field missing. Presence is unknown, not failed. |
| `keep`, or no entry | none | Raw value |

The *undeclared* reviewer mode ignores the header, as a person or model unaware of the scheme would. Comparing the two modes on the same view shows whether the scheme is merely lossy (unverifiable) or actively misleading (unsafe).

## Statuses and metrics

For each condition × view:

- **verified:** every authorised case confirmed this condition, and every generated violation of it was detected.
- **unverifiable:** at least one case left it undecided, and none was decided wrongly.
- **unsafe:** at least one wrong result: a false alarm on an authorised case, or a missed violation.
- **untested:** no case violates the condition (possible only with explicit pairs).

Per view (`summary.csv`):

- **Identical pairs:** matched pairs whose two inputs are byte-identical. Any decision rule must treat the two runs alike.
- **Ceiling:** the highest accuracy any yes/no decision based only on the input could reach on this case set.
  - It is not a safety indicator. Per-event pseudonyms give a perfect ceiling while making every authorised action look like a violation.
  - Merging identical inputs can never raise it.
- **Reviewer outcomes:** correct, missed violations, false alarms, insufficient evidence and definitive coverage, each with its denominator.
- **Exposure:** private values that appear verbatim, or JSON-escaped, in the reviewer's input. This is a lower bound on what leaks; format, timing and structure can leak more.

## Design rules this suggests

1. **Pseudonymise identities consistently over the smallest set the audit compares.** For one action against its authority, that set is one run. A keyed hash salted with the run identifier works in streaming pipelines; first-appearance aliases need the whole run.
2. **Keep the order of numbers even when you hide their values.** Within-run ranks of times and amounts keep every order decision exact. In the accounts-payable example they bring exposure to zero with every condition verified.
3. **Write authority state explicitly, as of the action.** Record "not revoked at execution", not the absence of a revocation.
4. **Declare every transformation** in the log itself.
5. **Test the production configuration as a CI gate,** with generated boundary violations.
