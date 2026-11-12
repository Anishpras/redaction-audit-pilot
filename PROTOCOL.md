# Protocol: What Evidence Do AI Agent Audit Logs Need After Redaction?

Pilot protocol. Version 1.0 was written and frozen (`FREEZE.json`, entry v1.0) before the main run on 2026-11-12. Only the pair-1 development check had run at that point. After an independent code review, a v1.1 revision tightened enforcement and corrected three statements; it did not change the rule, views, metrics, reviewer logic or fixture facts. Corrections are marked **[v1.1]** in place, and every change is listed under Revisions.

## 1. Question and hypotheses

**Question.** Take the same simulated document-sharing runs. If full audit logs are replaced with uniform masking or with consistent aliases, what happens to a reviewer's ability to verify that a completed share had consent?

**Unit of study.** One completed `share_document` action in a fictional CRM. Its effect is recorded by a mock executor, including deliberately unauthorised shares, and audited afterwards. This measures what the *log* lets a reviewer determine. It does not test a language model.

| | Hypothesis | Pre-specified prediction on this fixture set (self-attested) |
|---|---|---|
| H1 | Uniform masking makes some authorised/unauthorised pairs identical when the verdict depends on which document or recipient matches the grant. | View B: 6/10 pairs identical (4/4 recipient, 2/2 document, 0/2 expiry, 0/2 revocation). Ceiling 14/20 = 0.70. Reviewer: 4/20 correct (the four timing violations), 16/20 insufficient evidence, 0 missed violations, 0 false alarms, 0/10 authorised shares confirmed. |
| H2 | Consistent within-run aliases restore those relationships while removing direct exposure of planted values. | View C: 0/10 pairs identical, ceiling 1.00, reviewer 20/20 correct. Planted values visible: A 100%, B 0%, C 0%. |
| H3 | Removing expiry or revocation evidence from C leaves some decisions unresolved even though identity relationships are visible. | C without expiry: 2/10 pairs identical (the expiry pairs), ceiling 0.90. Reviewer 8/20 correct and 12/20 insufficient: all 10 authorised cases plus the 2 expiry violations. C without revocation: the same pattern, with the revocation pairs in place of the expiry pairs. |

Most of these predictions follow from the fixture design. The pilot tests whether the implementation behaves as the analysis says. It also makes the mechanism concrete and measurable. It is not an empirical discovery about real logs. Disagreements with the predictions will be reported.

## 2. Consent rule

Each case contains exactly one consent grant and one completed share. A share is **authorised** if and only if all of the following hold:

1. The grant and share match on document identifier, recipient identifier and purpose.
2. `grant.time <= share.time < grant.expires_at`.
3. No revocation is effective at execution. A revocation is effective if `revocation.effective_at <= share.time`.

Times are simulated integers. Expiry and revocation take effect at their recorded time, including when that equals the share time. A known absence of revocation is recorded explicitly as `{"status": "not_revoked"}`. An omitted `revocation` field is *missing evidence*, not absence. Grant and share facts are trusted values from the mock application. Conclusions are scoped to this fictional rule, the recorded completed effects and these cases.

## 3. Fixtures

There are ten hand-specified matched pairs (20 runs) in `pilot/fixtures.py`, rendered to `data/fixtures.json`. Each pair contains one authorised and one unauthorised share. Within a pair the two runs share every irrelevant detail and differ in one policy-relevant fact.

| Family | Pairs | Changed fact | Boundary cases included |
|---|---|---|---|
| Recipient | P01–P04 | Who receives the document. Consent is held by A, B, C and D in turn, so no one identity marks a run as authorised. | P04 shares exactly at grant time. P03 has a revocation recorded after the share. |
| Document | P05–P06 | Which document is shared (a sibling file of the same client; an unrelated sensitive file) | |
| Expiry | P07–P08 | The grant's expiry, relative to a fixed share time | P07 executes exactly at expiry |
| Revocation | P09–P10 | Whether a revocation is effective at execution | P09 revokes exactly at execution. P10 compares explicit not-revoked with revoked earlier. |

Pair 1 is the brief's anchor case: D1 / A / "case review", granted at 10, expiring at 30, not revoked, shared at 20 to A (authorised) or B (unauthorised). ~~Different pairs use different purposes and times~~ **[v1.1]** No two pairs share the same combination of purpose and timeline, so no masked inputs collide across pairs (B has 14 distinct inputs, C 20, each ablation 18). Individual values do recur: for example, P01 and P07 both use "case review" and grant time 10.

**Manifest.** `data/manifest.json` stores each case's hand-written expected verdict, rationale, pair ID, family and changed fact. Records carry only `case_id` and an arbitrary `run_id` for joining. No view includes either. **[v1.1]** Case IDs are opaque hashes (`case-xxxxxxxx`) instead of `P01-auth`, and records are stored in case-ID order, so neither the IDs nor the storage position carries the label. Labels are joined to reviewer output only after the reviewer has run.

**Sanity cases (separate from the 20).** There are five verdict-preserving variants: S1, S2 and S5 change fictional names or titles, S3 changes the stored key order (seed 20261112), and S4 changes the raw identifier format. The verdict must not change in any view. Masked and aliased views must be byte-identical to the base case. The full view must be byte-identical only for the key-order change.

## 4. Views and private fields

The **private fields** below were decided before the run, along with the reasons:

| Field | Category | Why private | Needed to verify consent? |
|---|---|---|---|
| `document.id`, `recipient.id` | identifier | Directly identifies a client record or a person | Only for **equality** between grant and share. The raw value itself is not needed. |
| `document.title`, `recipient.name` | name | Directly identifying, and often contains client names | No |
| `document.excerpt`, share `message` | content | The sensitive payload, which can embed further identifiers | No |

**Retained in every view:** event type, action, actor role, outcome, purpose, grant time, share time, expiry and revocation. These are the facts the rule needs. Purposes are treated as non-private policy categories (see Limitations).

All views are generated from the same underlying record. They drop `case_id` and `run_id` and preserve event order (grant, then share). They are serialised as canonical JSON (sorted keys, no whitespace, ASCII). Those exact bytes are what the reviewer receives, and they are what the identical-input comparison uses.

- **A. Full evidence.** All synthetic raw values.
- **B. Uniform masking.** `document.id` becomes `[MASKED:document_id]` and `recipient.id` becomes `[MASKED:recipient_id]`. Names become `[MASKED:name]` and contents become `[MASKED:content]`.
- **C. Consistent aliases.** Names and contents are masked as in B. Identifiers become `DOC_ALIAS_n` / `RCP_ALIAS_n`, numbered by first appearance in a fixed traversal: events in order, document before recipient within each event. Each type has its own counter, and the counters reset for every run.
- **C ablations.** `C_no_expiry` drops `expires_at` from the grant. `C_no_revocation` drops the whole `revocation` object, including an explicit "not revoked".

## 5. Reviewer

`pilot/reviewer.py` is a standalone script that imports only `json` and `sys`. It reads one log on stdin and writes one verdict on stdout. It runs under `python3 -I` with an empty environment and an empty working directory.

It evaluates each of six conditions (document, recipient, purpose, at-or-after-grant, before-expiry, not-revoked) as pass, fail or unknown:

- A uniform mask is **unknown**, even when the grant's and share's masks are the same string.
- Aliases and raw identifiers are compared by equality within the run.
- A missing field is unknown.

Any known fail gives **unauthorised**. All six passing gives **authorised**. Otherwise the verdict is **insufficient_evidence**.

## 6. Metrics

1. **Identical pairs.** Matched pairs whose two exact inputs are byte-identical while their expected verdicts differ, reported out of 10 and by family.
2. **Ceiling.** Group all 20 runs by identical input bytes and sum the larger label count in each group, then divide by 20. This is the highest accuracy that any forced binary decision based only on the visible input could reach *on this fixed fixture set*. It is reported separately from reviewer performance.
3. **Reviewer performance.** Correct out of 20. Missed violations (unauthorised judged authorised) out of 10. False alarms (authorised judged unauthorised) out of 10. Insufficient-evidence decisions out of 20, split by true label. Definitive-answer coverage out of 20. All are also reported by family.
4. **Direct exposure.** Distinct planted values (the private-field values of the underlying record) that appear verbatim, or in JSON-escaped form, in the exact input. Reported as distinct values over all planted values, summed per input, and by category.

**Supplementary diagnostic (not a pre-specified metric).** The view-B inputs are re-run with the reviewer told to compare mask strings as if they were real identifiers. This shows how a careless reviewer would misread equal masks.

## 7. Validation (before interpreting any result)

- Every hand label equals the trusted-fact oracle (`pilot/policy.py`, a separate implementation).
- Every pair differs only in its intended fact, and the unauthorised case fails exactly one condition. Family counts are 4/2/2/2. The two required boundary cases are present.
- The reviewer's imports and calls are checked statically. Its inputs contain no case, pair or run IDs, no label vocabulary and nothing except the event list.
- Canonical bytes are repeatable and do not depend on the source key order. (These two checks are weak: the serialiser is a pure function, and sorted keys make key-order independence nearly certain.)
- Positive control: the scanner finds 100% of planted values in view A. Negative control: it finds none in a string built from retained text.
- The full-view reviewer must match all 20 labels before any other view is interpreted (a gate).
- A second complete pass must reproduce every input and verdict. The result files, apart from `run_info.json`, must be byte-identical across invocations. (Cross-invocation identity is checked by hand with `diff`; it is not an automated check.)
- **[v1.1]** The stored `data/` must equal what `pilot/fixtures.py` produces, and every frozen file (including all code) must match the latest `FREEZE.json` entry. Both are failing checks.
- **[v1.1]** Metric invariants hold in every view:
  - the reviewer's correct count does not exceed the ceiling's majority sum, which no stateless reviewer can beat;
  - the outcome counts partition the 20 runs;
  - for these five views, in which every unauthorised run that shows no failing condition is byte-identical to its authorised partner, the ceiling's majority sum equals the authorised runs plus the violations detected. This identity is not general: a view that adds per-event randomness can break it.
- The sanity cases behave as specified in section 3.
- Every mixed-label identical-input group, and at least one pair from each family, is inspected by hand and reported.

## 8. Reporting

The report gives descriptive counts only, with no inferential statistics. The fixture set is small and constructed, so no rate generalises beyond it. The fixed design determines, among other things: which fact varies, the use of one grant and one share per case, integer clocks, trusted facts, no cross-pair collisions of inputs, and mask strings that announce themselves.

## Revisions

### v1.1 (2026-11-12, after the main run; prompted by an independent code review)

The independent reviewer recomputed every metric with its own code and confirmed all reported numbers. These changes therefore tighten enforcement and correct statements. **No reported number changed:** `results/summary.csv` and `results/family_breakdown.csv` are byte-identical to v1.0.

1. **Freeze enforcement.**
   - In v1.0, a mismatch with `FREEZE.json` was only printed, the run rewrote `data/` before comparing, and the hashes did not cover the code.
   - Now the default command never writes `data/`; regenerating it needs `--rebuild-fixtures`.
   - Both the data check and the freeze check fail the run.
   - The freeze hashes all code and tests. `FREEZE.json` keeps the v1.0 entry as history.
2. **Reviewer isolation.** Every call now gets a fresh temporary directory containing only a copy of the reviewer. `argv[0]` is then a bare filename that reveals no project path, and call order is shuffled with recorded seeds (20261113, 20261114). This is process-level isolation, not an OS sandbox.
3. **Static check.** The reviewer check is now an allowlist of imports, attributes and calls, with no dunder access. It catches indirect access such as `json.codecs.open`.
4. **Opaque case IDs** and a label-free record order (see §3).
5. **New tests.** Reviewer purpose-mismatch tests in every view; grant-time boundary tests in views B and C; an alias-reset test that renders two runs; a test that the static check rejects indirect file access; and scoring tests on toy inputs with hand-computed answers. That makes 30 unit tests, up from 21.
6. **New checks.** Boundary checks are now tied to their intended pairs (P07, P09, P04, P03). The metric invariants of §7 were added. The full-view gate now stops the run instead of only printing a message.
7. **Corrected statements.**
   - "different pairs use different purposes and times" (see §3);
   - the paper's claim that shared timelines would lower B's ceiling. For these five views, every ceiling equals (authorised runs + unauthorised runs whose own input shows a failing condition) / 20, whatever collides.
8. **Supplementary analysis, not pre-specified.** A shared-timeline variant moves every pair onto P01's purpose and timeline. Inputs collide across pairs, but every ceiling and every reviewer count stays the same as in the main fixtures.

Mutation tests confirm the new safeguards. Each of five deliberate faults is caught: an edited fixture, an alias table that persists across runs, a reviewer that always passes purpose, scoring that counts abstentions as misses, and a reviewer that reaches the filesystem through `json.codecs`.


### v1.1.1 (2026-11-12, wording only; prompted by a second independent review)

No code, data or results changed.

- **Property (ii) of the ceiling, scoped.** It is now stated as holding for views in which every unauthorised run that shows no failing condition is byte-identical to its partner, as all five views here are. It is not a general property of matched-pair designs: a per-event random mask breaks it.
- **"Pre-registered" replaced by "pre-specified (self-attested)".** `FREEZE.json` is written by the author, and the v1.0 hashes refer to files with the original case identifiers, which are not in the release.
- **"Every definitive answer was correct", scoped to the five views tested.**
