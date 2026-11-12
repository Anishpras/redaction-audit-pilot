# Example: accounts-payable agent executing supplier payments

This policy, its cases and the `ap_redactor.py` script were written during the toolkit's usability test, by an AI agent acting as a first-time user. They were then adapted to v1.2 features: `four_eyes` uses `relation: different`, amounts are a private category, and the IBAN violation uses the default format-preserving mutation.

```bash
X=examples/accounts-payable
python3 -m redaction_audit run --policy $X/policy.json --fields $X/fields.json --cases $X/cases.jsonl \
  --views $X/views.json --out $X/results
```

**The rule.** A payment is authorised only if all 12 of the following hold:

1. An approval exists for the same invoice.
2. The approver belongs to the same cost centre.
3. The currency matches.
4. The amount is within the approved amount.
5. The approval was granted before the payment.
6. The approval had not expired.
7. The approval had not been withdrawn.
8. The approver is a manager.
9. The approver is not the requester (four-eyes).
10. The payee IBAN matches the vendor-master check.
11. The payee is allowlisted.
12. An invoice document is attached.

**The data.** Five authorised payment logs, one of them containing a failed attempt followed by a retry, produce 60 generated boundary violations.

**What the results say** (`results/matrix.md`):

| View | Result |
|---|---|
| `vendor_default_mask` (every private value replaced by its type) | Loses the invoice, amount, four-eyes and payee checks. Read without its header it is UNSAFE. |
| `prod_current` (global keyed hash, times floored to the hour) | Cannot clear the time-based conditions near their limits, and misleads a reader who doesn't know about the buckets |
| `amounts_banded` | Hides amounts but makes `amount_within_approval` unverifiable. Read literally it is UNSAFE. |
| `iban_last4_declared` | The payee check is honestly unverifiable while the header is present, and UNSAFE without it |
| `ap_redactor` (in-house regex scrubber; keeps IBAN endings without declaring them) | **UNSAFE**: 4 lookalike-IBAN payments pass. It also leaves 44 of 81 private values visible (see `results/exposure.csv`). |
| `prod_proposed_amounts_ranked` (per-run keyed hash; names and text masked; times and amounts replaced by their order within the run) | **Every condition verified, in both readings, with 0 of 81 private values visible** |

The pseudonym views use a literal example key. In production use `"key_env": "YOUR_SECRET_VAR"`.
