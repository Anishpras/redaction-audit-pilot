# Condition x view matrix: Consent-based document sharing (pilot rule)

Status per condition and view: **verified** (every authorised case confirmed and every targeted violation detected), **unverifiable** (some cases left undecided) or **UNSAFE** (the reviewer gave at least one wrong verdict). **untested** means no case violates the condition, so a reviewer that wrongly passes it would not be caught.

| Condition | Need | A_full | B_uniform_mask | C_alias | C_no_expiry | C_no_revocation | D_pseudonym_event | E_pseudonym_run | F_pseudonym_global | G_times_bucket10 | H_times_rank | I_purpose_masked |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| document_matches | equality | verified | **UNSAFE** | verified | verified | verified | **UNSAFE** | verified | verified | verified | verified | verified |
| recipient_matches | equality | verified | **UNSAFE** | verified | verified | verified | **UNSAFE** | verified | verified | verified | verified | verified |
| purpose_matches | equality | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested |
| at_or_after_grant | order | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested |
| before_expiry | order | verified | verified | verified | unverifiable | verified | verified | verified | verified | **UNSAFE** | verified | verified |
| not_revoked | explicit_state | verified | verified | verified | verified | unverifiable | verified | verified | verified | **UNSAFE** | verified | verified |

## Counts (declared reading)

Authorised side: confirmed / unconfirmed / false alarms. Violation side (cases targeting this condition): detected / undetected / missed. Collapsed: targeted pairs whose two inputs are byte-identical.

| View | Condition | Status | Authorised (conf/unconf/false) | Violations (det/undet/missed) | Collapsed |
|---|---|---|---|---|---|
| A_full | document_matches | verified | 10/0/0 | 2/0/0 | 0/2 |
| A_full | recipient_matches | verified | 10/0/0 | 4/0/0 | 0/4 |
| A_full | purpose_matches | untested | 10/0/0 | 0/0/0 | 0/0 |
| A_full | at_or_after_grant | untested | 10/0/0 | 0/0/0 | 0/0 |
| A_full | before_expiry | verified | 10/0/0 | 2/0/0 | 0/2 |
| A_full | not_revoked | verified | 10/0/0 | 2/0/0 | 0/2 |
| B_uniform_mask | document_matches | unsafe | 10/0/0 | 0/0/2 | 2/2 |
| B_uniform_mask | recipient_matches | unsafe | 10/0/0 | 0/0/4 | 4/4 |
| B_uniform_mask | purpose_matches | untested | 10/0/0 | 0/0/0 | 0/0 |
| B_uniform_mask | at_or_after_grant | untested | 10/0/0 | 0/0/0 | 0/0 |
| B_uniform_mask | before_expiry | verified | 10/0/0 | 2/0/0 | 0/2 |
| B_uniform_mask | not_revoked | verified | 10/0/0 | 2/0/0 | 0/2 |
| C_alias | document_matches | verified | 10/0/0 | 2/0/0 | 0/2 |
| C_alias | recipient_matches | verified | 10/0/0 | 4/0/0 | 0/4 |
| C_alias | purpose_matches | untested | 10/0/0 | 0/0/0 | 0/0 |
| C_alias | at_or_after_grant | untested | 10/0/0 | 0/0/0 | 0/0 |
| C_alias | before_expiry | verified | 10/0/0 | 2/0/0 | 0/2 |
| C_alias | not_revoked | verified | 10/0/0 | 2/0/0 | 0/2 |
| C_no_expiry | document_matches | verified | 10/0/0 | 2/0/0 | 0/2 |
| C_no_expiry | recipient_matches | verified | 10/0/0 | 4/0/0 | 0/4 |
| C_no_expiry | purpose_matches | untested | 10/0/0 | 0/0/0 | 0/0 |
| C_no_expiry | at_or_after_grant | untested | 10/0/0 | 0/0/0 | 0/0 |
| C_no_expiry | before_expiry | unverifiable | 0/10/0 | 0/2/0 | 2/2 |
| C_no_expiry | not_revoked | verified | 10/0/0 | 2/0/0 | 0/2 |
| C_no_revocation | document_matches | verified | 10/0/0 | 2/0/0 | 0/2 |
| C_no_revocation | recipient_matches | verified | 10/0/0 | 4/0/0 | 0/4 |
| C_no_revocation | purpose_matches | untested | 10/0/0 | 0/0/0 | 0/0 |
| C_no_revocation | at_or_after_grant | untested | 10/0/0 | 0/0/0 | 0/0 |
| C_no_revocation | before_expiry | verified | 10/0/0 | 2/0/0 | 0/2 |
| C_no_revocation | not_revoked | unverifiable | 0/10/0 | 0/2/0 | 2/2 |
| D_pseudonym_event | document_matches | unsafe | 0/0/10 | 2/0/0 | 0/2 |
| D_pseudonym_event | recipient_matches | unsafe | 0/0/10 | 4/0/0 | 0/4 |
| D_pseudonym_event | purpose_matches | untested | 10/0/0 | 0/0/0 | 0/0 |
| D_pseudonym_event | at_or_after_grant | untested | 10/0/0 | 0/0/0 | 0/0 |
| D_pseudonym_event | before_expiry | verified | 10/0/0 | 2/0/0 | 0/2 |
| D_pseudonym_event | not_revoked | verified | 10/0/0 | 2/0/0 | 0/2 |
| E_pseudonym_run | document_matches | verified | 10/0/0 | 2/0/0 | 0/2 |
| E_pseudonym_run | recipient_matches | verified | 10/0/0 | 4/0/0 | 0/4 |
| E_pseudonym_run | purpose_matches | untested | 10/0/0 | 0/0/0 | 0/0 |
| E_pseudonym_run | at_or_after_grant | untested | 10/0/0 | 0/0/0 | 0/0 |
| E_pseudonym_run | before_expiry | verified | 10/0/0 | 2/0/0 | 0/2 |
| E_pseudonym_run | not_revoked | verified | 10/0/0 | 2/0/0 | 0/2 |
| F_pseudonym_global | document_matches | verified | 10/0/0 | 2/0/0 | 0/2 |
| F_pseudonym_global | recipient_matches | verified | 10/0/0 | 4/0/0 | 0/4 |
| F_pseudonym_global | purpose_matches | untested | 10/0/0 | 0/0/0 | 0/0 |
| F_pseudonym_global | at_or_after_grant | untested | 10/0/0 | 0/0/0 | 0/0 |
| F_pseudonym_global | before_expiry | verified | 10/0/0 | 2/0/0 | 0/2 |
| F_pseudonym_global | not_revoked | verified | 10/0/0 | 2/0/0 | 0/2 |
| G_times_bucket10 | document_matches | verified | 10/0/0 | 2/0/0 | 0/2 |
| G_times_bucket10 | recipient_matches | verified | 10/0/0 | 4/0/0 | 0/4 |
| G_times_bucket10 | purpose_matches | untested | 10/0/0 | 0/0/0 | 0/0 |
| G_times_bucket10 | at_or_after_grant | untested | 10/0/0 | 0/0/0 | 0/0 |
| G_times_bucket10 | before_expiry | unsafe | 9/0/1 | 2/0/0 | 1/2 |
| G_times_bucket10 | not_revoked | unsafe | 9/0/1 | 2/0/0 | 1/2 |
| H_times_rank | document_matches | verified | 10/0/0 | 2/0/0 | 0/2 |
| H_times_rank | recipient_matches | verified | 10/0/0 | 4/0/0 | 0/4 |
| H_times_rank | purpose_matches | untested | 10/0/0 | 0/0/0 | 0/0 |
| H_times_rank | at_or_after_grant | untested | 10/0/0 | 0/0/0 | 0/0 |
| H_times_rank | before_expiry | verified | 10/0/0 | 2/0/0 | 0/2 |
| H_times_rank | not_revoked | verified | 10/0/0 | 2/0/0 | 0/2 |
| I_purpose_masked | document_matches | verified | 10/0/0 | 2/0/0 | 0/2 |
| I_purpose_masked | recipient_matches | verified | 10/0/0 | 4/0/0 | 0/4 |
| I_purpose_masked | purpose_matches | untested | 10/0/0 | 0/0/0 | 0/0 |
| I_purpose_masked | at_or_after_grant | untested | 10/0/0 | 0/0/0 | 0/0 |
| I_purpose_masked | before_expiry | verified | 10/0/0 | 2/0/0 | 0/2 |
| I_purpose_masked | not_revoked | verified | 10/0/0 | 2/0/0 | 0/2 |

## Cases behind each problem (declared reading)

Authorised cases are named by case id, violations by pair id (base~condition). Exact inputs are in inputs/<view>/<case id>.json.

- **B_uniform_mask / document_matches:** missed: P05, P06
- **B_uniform_mask / recipient_matches:** missed: P01, P02, P03, P04
- **C_no_expiry / before_expiry:** unconfirmed: case-e44e723a, case-3174a658, case-fb111b84, case-06e7f66e, case-d4bafa2e, case-3a22e53d and 4 more; undetected: P07, P08
- **C_no_revocation / not_revoked:** unconfirmed: case-e44e723a, case-3174a658, case-fb111b84, case-06e7f66e, case-d4bafa2e, case-3a22e53d and 4 more; undetected: P09, P10
- **D_pseudonym_event / document_matches:** false alarm: case-e44e723a, case-3174a658, case-fb111b84, case-06e7f66e, case-d4bafa2e, case-3a22e53d and 4 more
- **D_pseudonym_event / recipient_matches:** false alarm: case-e44e723a, case-3174a658, case-fb111b84, case-06e7f66e, case-d4bafa2e, case-3a22e53d and 4 more
- **G_times_bucket10 / before_expiry:** false alarm: case-cadaeb1b
- **G_times_bucket10 / not_revoked:** false alarm: case-5d882f0b
