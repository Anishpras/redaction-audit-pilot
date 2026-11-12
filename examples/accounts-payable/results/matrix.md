# Condition x view matrix: AP agent executes a supplier payment

Status per condition and view: **verified** (every authorised case confirmed and every targeted violation detected), **unverifiable** (some cases left undecided) or **UNSAFE** (the reviewer gave at least one wrong verdict). **untested** means no case violates the condition, so a reviewer that wrongly passes it would not be caught.

| Condition | Need | full | vendor_default_mask | alias_per_run | prod_current | prod_proposed | amounts_banded | prod_proposed_amounts_ranked | iban_last4_declared | ap_redactor |
|---|---|---|---|---|---|---|---|---|---|---|
| same_invoice | equality | verified | unverifiable | verified | verified | verified | verified | verified | verified | verified |
| same_cost_centre | equality | verified | verified | verified | verified | verified | verified | verified | verified | verified |
| same_currency | equality | verified | verified | verified | verified | verified | verified | verified | verified | verified |
| amount_within_approval | order | verified | unverifiable | verified | verified | verified | unverifiable | verified | verified | verified |
| approved_before_payment | order | verified | verified | verified | unverifiable | verified | verified | verified | verified | unverifiable |
| approval_not_expired | order | verified | verified | verified | unverifiable | verified | verified | verified | verified | unverifiable |
| approval_not_withdrawn | explicit_state | verified | verified | verified | unverifiable | verified | verified | verified | verified | unverifiable |
| approver_is_manager | raw_value | verified | verified | verified | verified | verified | verified | verified | verified | verified |
| four_eyes | equality | verified | unverifiable | verified | verified | verified | verified | verified | verified | verified |
| payee_checked | equality | verified | unverifiable | verified | verified | verified | verified | verified | unverifiable | **UNSAFE** |
| payee_allowlisted | explicit_state | verified | verified | verified | verified | verified | verified | verified | verified | verified |
| invoice_document_attached | presence | verified | verified | verified | verified | verified | verified | verified | verified | verified |

## Same views read without the redaction header (undeclared reading)

What a reviewer who does not know how the log was redacted would conclude. Cells that are **UNSAFE** here but not above mean the scheme is safe only while its declaration travels with the log.

| Condition | Need | full | vendor_default_mask | alias_per_run | prod_current | prod_proposed | amounts_banded | prod_proposed_amounts_ranked | iban_last4_declared | ap_redactor |
|---|---|---|---|---|---|---|---|---|---|---|
| same_invoice | equality | verified | **UNSAFE** | verified | verified | verified | verified | verified | verified | verified |
| same_cost_centre | equality | verified | verified | verified | verified | verified | verified | verified | verified | verified |
| same_currency | equality | verified | verified | verified | verified | verified | verified | verified | verified | verified |
| amount_within_approval | order | verified | unverifiable | verified | verified | verified | **UNSAFE** | verified | verified | verified |
| approved_before_payment | order | verified | verified | verified | **UNSAFE** | verified | verified | verified | verified | **UNSAFE** |
| approval_not_expired | order | verified | verified | verified | **UNSAFE** | verified | verified | verified | verified | verified |
| approval_not_withdrawn | explicit_state | verified | verified | verified | verified | verified | verified | verified | verified | verified |
| approver_is_manager | raw_value | verified | verified | verified | verified | verified | verified | verified | verified | verified |
| four_eyes | equality | verified | **UNSAFE** | verified | verified | verified | verified | verified | verified | verified |
| payee_checked | equality | verified | **UNSAFE** | verified | verified | verified | verified | verified | **UNSAFE** | **UNSAFE** |
| payee_allowlisted | explicit_state | verified | verified | verified | verified | verified | verified | verified | verified | verified |
| invoice_document_attached | presence | verified | verified | verified | verified | verified | verified | verified | verified | verified |

## Counts (declared reading)

Authorised side: confirmed / unconfirmed / false alarms. Violation side (cases targeting this condition): detected / undetected / missed. Collapsed: targeted pairs whose two inputs are byte-identical.

| View | Condition | Status | Authorised (conf/unconf/false) | Violations (det/undet/missed) | Collapsed |
|---|---|---|---|---|---|
| full | same_invoice | verified | 5/0/0 | 5/0/0 | 0/5 |
| full | same_cost_centre | verified | 5/0/0 | 5/0/0 | 0/5 |
| full | same_currency | verified | 5/0/0 | 5/0/0 | 0/5 |
| full | amount_within_approval | verified | 5/0/0 | 5/0/0 | 0/5 |
| full | approved_before_payment | verified | 5/0/0 | 5/0/0 | 0/5 |
| full | approval_not_expired | verified | 5/0/0 | 5/0/0 | 0/5 |
| full | approval_not_withdrawn | verified | 5/0/0 | 5/0/0 | 0/5 |
| full | approver_is_manager | verified | 5/0/0 | 5/0/0 | 0/5 |
| full | four_eyes | verified | 5/0/0 | 5/0/0 | 0/5 |
| full | payee_checked | verified | 5/0/0 | 5/0/0 | 0/5 |
| full | payee_allowlisted | verified | 5/0/0 | 5/0/0 | 0/5 |
| full | invoice_document_attached | verified | 5/0/0 | 5/0/0 | 0/5 |
| vendor_default_mask | same_invoice | unverifiable | 0/5/0 | 0/5/0 | 5/5 |
| vendor_default_mask | same_cost_centre | verified | 5/0/0 | 5/0/0 | 0/5 |
| vendor_default_mask | same_currency | verified | 5/0/0 | 5/0/0 | 0/5 |
| vendor_default_mask | amount_within_approval | unverifiable | 0/5/0 | 0/5/0 | 5/5 |
| vendor_default_mask | approved_before_payment | verified | 5/0/0 | 5/0/0 | 0/5 |
| vendor_default_mask | approval_not_expired | verified | 5/0/0 | 5/0/0 | 0/5 |
| vendor_default_mask | approval_not_withdrawn | verified | 5/0/0 | 5/0/0 | 0/5 |
| vendor_default_mask | approver_is_manager | verified | 5/0/0 | 5/0/0 | 0/5 |
| vendor_default_mask | four_eyes | unverifiable | 0/5/0 | 0/5/0 | 5/5 |
| vendor_default_mask | payee_checked | unverifiable | 0/5/0 | 0/5/0 | 5/5 |
| vendor_default_mask | payee_allowlisted | verified | 5/0/0 | 5/0/0 | 0/5 |
| vendor_default_mask | invoice_document_attached | verified | 5/0/0 | 5/0/0 | 0/5 |
| alias_per_run | same_invoice | verified | 5/0/0 | 5/0/0 | 0/5 |
| alias_per_run | same_cost_centre | verified | 5/0/0 | 5/0/0 | 0/5 |
| alias_per_run | same_currency | verified | 5/0/0 | 5/0/0 | 0/5 |
| alias_per_run | amount_within_approval | verified | 5/0/0 | 5/0/0 | 0/5 |
| alias_per_run | approved_before_payment | verified | 5/0/0 | 5/0/0 | 0/5 |
| alias_per_run | approval_not_expired | verified | 5/0/0 | 5/0/0 | 0/5 |
| alias_per_run | approval_not_withdrawn | verified | 5/0/0 | 5/0/0 | 0/5 |
| alias_per_run | approver_is_manager | verified | 5/0/0 | 5/0/0 | 0/5 |
| alias_per_run | four_eyes | verified | 5/0/0 | 5/0/0 | 0/5 |
| alias_per_run | payee_checked | verified | 5/0/0 | 5/0/0 | 0/5 |
| alias_per_run | payee_allowlisted | verified | 5/0/0 | 5/0/0 | 0/5 |
| alias_per_run | invoice_document_attached | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_current | same_invoice | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_current | same_cost_centre | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_current | same_currency | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_current | amount_within_approval | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_current | approved_before_payment | unverifiable | 4/1/0 | 0/5/0 | 1/5 |
| prod_current | approval_not_expired | unverifiable | 4/1/0 | 0/5/0 | 1/5 |
| prod_current | approval_not_withdrawn | unverifiable | 5/0/0 | 0/5/0 | 0/5 |
| prod_current | approver_is_manager | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_current | four_eyes | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_current | payee_checked | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_current | payee_allowlisted | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_current | invoice_document_attached | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed | same_invoice | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed | same_cost_centre | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed | same_currency | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed | amount_within_approval | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed | approved_before_payment | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed | approval_not_expired | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed | approval_not_withdrawn | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed | approver_is_manager | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed | four_eyes | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed | payee_checked | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed | payee_allowlisted | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed | invoice_document_attached | verified | 5/0/0 | 5/0/0 | 0/5 |
| amounts_banded | same_invoice | verified | 5/0/0 | 5/0/0 | 0/5 |
| amounts_banded | same_cost_centre | verified | 5/0/0 | 5/0/0 | 0/5 |
| amounts_banded | same_currency | verified | 5/0/0 | 5/0/0 | 0/5 |
| amounts_banded | amount_within_approval | unverifiable | 2/3/0 | 1/4/0 | 2/5 |
| amounts_banded | approved_before_payment | verified | 5/0/0 | 5/0/0 | 0/5 |
| amounts_banded | approval_not_expired | verified | 5/0/0 | 5/0/0 | 0/5 |
| amounts_banded | approval_not_withdrawn | verified | 5/0/0 | 5/0/0 | 0/5 |
| amounts_banded | approver_is_manager | verified | 5/0/0 | 5/0/0 | 0/5 |
| amounts_banded | four_eyes | verified | 5/0/0 | 5/0/0 | 0/5 |
| amounts_banded | payee_checked | verified | 5/0/0 | 5/0/0 | 0/5 |
| amounts_banded | payee_allowlisted | verified | 5/0/0 | 5/0/0 | 0/5 |
| amounts_banded | invoice_document_attached | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed_amounts_ranked | same_invoice | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed_amounts_ranked | same_cost_centre | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed_amounts_ranked | same_currency | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed_amounts_ranked | amount_within_approval | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed_amounts_ranked | approved_before_payment | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed_amounts_ranked | approval_not_expired | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed_amounts_ranked | approval_not_withdrawn | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed_amounts_ranked | approver_is_manager | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed_amounts_ranked | four_eyes | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed_amounts_ranked | payee_checked | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed_amounts_ranked | payee_allowlisted | verified | 5/0/0 | 5/0/0 | 0/5 |
| prod_proposed_amounts_ranked | invoice_document_attached | verified | 5/0/0 | 5/0/0 | 0/5 |
| iban_last4_declared | same_invoice | verified | 5/0/0 | 5/0/0 | 0/5 |
| iban_last4_declared | same_cost_centre | verified | 5/0/0 | 5/0/0 | 0/5 |
| iban_last4_declared | same_currency | verified | 5/0/0 | 5/0/0 | 0/5 |
| iban_last4_declared | amount_within_approval | verified | 5/0/0 | 5/0/0 | 0/5 |
| iban_last4_declared | approved_before_payment | verified | 5/0/0 | 5/0/0 | 0/5 |
| iban_last4_declared | approval_not_expired | verified | 5/0/0 | 5/0/0 | 0/5 |
| iban_last4_declared | approval_not_withdrawn | verified | 5/0/0 | 5/0/0 | 0/5 |
| iban_last4_declared | approver_is_manager | verified | 5/0/0 | 5/0/0 | 0/5 |
| iban_last4_declared | four_eyes | verified | 5/0/0 | 5/0/0 | 0/5 |
| iban_last4_declared | payee_checked | unverifiable | 0/5/0 | 0/5/0 | 5/5 |
| iban_last4_declared | payee_allowlisted | verified | 5/0/0 | 5/0/0 | 0/5 |
| iban_last4_declared | invoice_document_attached | verified | 5/0/0 | 5/0/0 | 0/5 |
| ap_redactor | same_invoice | verified | 5/0/0 | 5/0/0 | 0/5 |
| ap_redactor | same_cost_centre | verified | 5/0/0 | 5/0/0 | 0/5 |
| ap_redactor | same_currency | verified | 5/0/0 | 5/0/0 | 0/5 |
| ap_redactor | amount_within_approval | verified | 5/0/0 | 5/0/0 | 0/5 |
| ap_redactor | approved_before_payment | unverifiable | 4/1/0 | 1/4/0 | 1/5 |
| ap_redactor | approval_not_expired | unverifiable | 5/0/0 | 0/5/0 | 0/5 |
| ap_redactor | approval_not_withdrawn | unverifiable | 5/0/0 | 0/5/0 | 0/5 |
| ap_redactor | approver_is_manager | verified | 5/0/0 | 5/0/0 | 0/5 |
| ap_redactor | four_eyes | verified | 5/0/0 | 5/0/0 | 0/5 |
| ap_redactor | payee_checked | unsafe | 5/0/0 | 0/0/5 | 5/5 |
| ap_redactor | payee_allowlisted | verified | 5/0/0 | 5/0/0 | 0/5 |
| ap_redactor | invoice_document_attached | verified | 5/0/0 | 5/0/0 | 0/5 |

## Cases behind each problem (declared reading)

Authorised cases are named by case id, violations by pair id (base~condition). Exact inputs are in inputs/<view>/<case id>.json.

- **vendor_default_mask / same_invoice:** unconfirmed: ap-01, ap-02, ap-03, ap-04, ap-05; undetected: ap-01~same_invoice, ap-02~same_invoice, ap-03~same_invoice, ap-04~same_invoice, ap-05~same_invoice
- **vendor_default_mask / amount_within_approval:** unconfirmed: ap-01, ap-02, ap-03, ap-04, ap-05; undetected: ap-01~amount_within_approval, ap-02~amount_within_approval, ap-03~amount_within_approval, ap-04~amount_within_approval, ap-05~amount_within_approval
- **vendor_default_mask / four_eyes:** unconfirmed: ap-01, ap-02, ap-03, ap-04, ap-05; undetected: ap-01~four_eyes, ap-02~four_eyes, ap-03~four_eyes, ap-04~four_eyes, ap-05~four_eyes
- **vendor_default_mask / payee_checked:** unconfirmed: ap-01, ap-02, ap-03, ap-04, ap-05; undetected: ap-01~payee_checked, ap-02~payee_checked, ap-03~payee_checked, ap-04~payee_checked, ap-05~payee_checked
- **prod_current / approved_before_payment:** unconfirmed: ap-04; undetected: ap-01~approved_before_payment, ap-02~approved_before_payment, ap-03~approved_before_payment, ap-04~approved_before_payment, ap-05~approved_before_payment
- **prod_current / approval_not_expired:** unconfirmed: ap-02; undetected: ap-01~approval_not_expired, ap-02~approval_not_expired, ap-03~approval_not_expired, ap-04~approval_not_expired, ap-05~approval_not_expired
- **prod_current / approval_not_withdrawn:** undetected: ap-01~approval_not_withdrawn, ap-02~approval_not_withdrawn, ap-03~approval_not_withdrawn, ap-04~approval_not_withdrawn, ap-05~approval_not_withdrawn
- **amounts_banded / amount_within_approval:** unconfirmed: ap-02, ap-03, ap-04; undetected: ap-01~amount_within_approval, ap-03~amount_within_approval, ap-04~amount_within_approval, ap-05~amount_within_approval
- **iban_last4_declared / payee_checked:** unconfirmed: ap-01, ap-02, ap-03, ap-04, ap-05; undetected: ap-01~payee_checked, ap-02~payee_checked, ap-03~payee_checked, ap-04~payee_checked, ap-05~payee_checked
- **ap_redactor / approved_before_payment:** unconfirmed: ap-04; undetected: ap-01~approved_before_payment, ap-03~approved_before_payment, ap-04~approved_before_payment, ap-05~approved_before_payment
- **ap_redactor / approval_not_expired:** undetected: ap-01~approval_not_expired, ap-02~approval_not_expired, ap-03~approval_not_expired, ap-04~approval_not_expired, ap-05~approval_not_expired
- **ap_redactor / approval_not_withdrawn:** undetected: ap-01~approval_not_withdrawn, ap-02~approval_not_withdrawn, ap-03~approval_not_withdrawn, ap-04~approval_not_withdrawn, ap-05~approval_not_withdrawn
- **ap_redactor / payee_checked:** missed: ap-01~payee_checked, ap-02~payee_checked, ap-03~payee_checked, ap-04~payee_checked, ap-05~payee_checked
