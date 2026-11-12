# Mapping to standards and common tools

The toolkit's files are standard-neutral: field paths plus evidence needs. This page shows how its concepts line up with formats practitioners already use. Statements are based on the pages linked below, fetched on 12 November 2026. Several are moving targets, so check the current version before you rely on them.

## OpenTelemetry GenAI semantic conventions (agent traces)

- **Status.** The conventions are marked "Development" on the `execute_tool` page.
- **What a tool span records.** An `execute_tool` span records the tool identity and call IDs. The arguments and result (`gen_ai.tool.call.arguments`, `gen_ai.tool.call.result`) are **Opt-In**, and each is flagged "may contain sensitive information".
- **Missing attributes.** The page defines no attribute for authorisation, consent, approval or a policy decision.
- **Implication.** If arguments are not captured, the action's recipient and document are not in the trace at all, which is a stronger loss than uniform masking. To make agent traces auditable, promote the evidence fields out of the arguments blob into dedicated attributes, under your own namespace rather than `gen_ai.*`. Pseudonymise identifiers consistently per trace, and declare the redaction.
- **Using the toolkit.** The starter audit (`redaction_audit/template`) already uses span-shaped events with an `attributes` object. Point the roles at `name` / `attributes.*` fields of your exported spans.
- **Source:** https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/execute-tool.md

## OCSF (security event schema)

- **The `delegation` object.** In OCSF 1.9.0 it is described as "a durable authorization context that a principal issues to a delegate" (an AI agent, for example). It has four attributes: `uid`, `created_time`, `issuer_uid` and `parent_uid`.
- **What it lacks.** It has **no expiry, scope, purpose or revocation-state attribute**.
- **Implication.** An event that carries only this object is in the same position as the pilot's ablated views: an authorisation that depends on expiry or revocation cannot be verified from the event alone. The facts must be joined from the issuing system, or added as extension attributes.
- **Sources:** https://schema.ocsf.io/objects/delegation , https://schema.ocsf.io/profiles/ai_operation

## ISO/IEC TS 27560 consent records (through the W3C DPV guide)

The ISO text is not free. The W3C Data Privacy Vocabularies community group publishes a free mapping guide (Final Community Group Report, 15 February 2026).

| Toolkit concept | 27560 / DPV term |
|---|---|
| Purpose | Purpose (`dpv:hasPurpose`) |
| Recipient | Recipients (`dpv:hasRecipient`) |
| Data | Personal data (`dpv:hasPersonalData`). An optional personal-data identifier (`dct:identifier`) can identify a specific instance; the guide's example hashes it. |
| Event time | Event time (`dct:date`) |
| Consent state | Consent state (`dpv:hasConsentStatus`). Withdrawal is a **state change**, for example "Consent Withdrawn", not a field on the original grant. |

- **Expiry.** The guide notes that `dct:valid` describes the record, not the consent event. Don't map an expiry onto it without care.
- **Recommendation.** Model revocation as an explicit consent-state record with its own time, and make the audited action carry or reference the state that was in force at execution. That is the `explicit_state` need.
- **Source:** https://w3c-cg.github.io/dpv/guides/consent-27560

## W3C PROV-O (explanatory vocabulary)

- **Mapping.** The action is a `prov:Activity`, the document a `prov:Entity`, and the agent a `prov:Agent` acting on behalf of a principal (`prov:actedOnBehalfOf`). The grant is the plan the activity follows, and expiry or revocation is its invalidation.
- **Use.** This is useful for explaining audit evidence, but rarely used as a logging format.
- **Source:** https://www.w3.org/TR/prov-o/

## Redaction tools

The Presidio anonymiser documentation states two defaults:

| Presidio behaviour | Toolkit view | What the audit shows |
|---|---|---|
| The default operator is **replace**; with no new value, the entity type is used (for example `<PHONE_NUMBER>`) | `mask` | Identity conditions become unverifiable, or UNSAFE if read literally |
| The **hash** operator: "Same PII value gets different hashes across different entities and calls (unless you provide a salt)" | `pseudonym` with scope `event` | Undeclared, every authorised action becomes a false alarm |
| The hash operator with a fixed salt | `pseudonym` with scope `global` (or per-run salt for `run`) | Equality-based conditions remain verifiable |

These are emulated by built-in ops. To test the real tool, wrap your configuration as an `exec` transform.

**Source:** https://presidio.dataprivacystack.org/anonymizer/
