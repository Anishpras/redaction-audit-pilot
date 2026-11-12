"""Metrics 1-4. Labels come only from the manifest, joined after the reviewer ran.

All counts are reported with explicit denominators as {"n": k, "of": m}.
"""
from __future__ import annotations

import hashlib
from collections import OrderedDict, defaultdict

from . import exposure

FAMILIES = ("recipient", "document", "expiry", "revocation")
AUTH, UNAUTH, ABSTAIN = "authorised", "unauthorised", "insufficient_evidence"


def frac(n, of):
    return OrderedDict([("n", n), ("of", of)])


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def outcome_type(expected: str, verdict: str) -> str:
    if verdict == expected:
        return "correct"
    if verdict == ABSTAIN:
        return "abstain"
    if expected == UNAUTH and verdict == AUTH:
        return "missed_violation"
    if expected == AUTH and verdict == UNAUTH:
        return "false_alarm"
    raise ValueError((expected, verdict))


# Metric 1 -------------------------------------------------------------------
def identical_pairs(inputs: dict, cases: list) -> OrderedDict:
    """Matched pairs whose two exact reviewer inputs are byte-identical while
    their expected verdicts differ."""
    pairs = defaultdict(list)
    for c in cases:
        pairs[c["pair_id"]].append(c)
    total, by_family = 0, OrderedDict((f, [0, 0]) for f in FAMILIES)
    identical_ids = []
    for pair_id in sorted(pairs):
        a, b = pairs[pair_id]
        fam = a["family"]
        by_family[fam][1] += 1
        if inputs[a["case_id"]] == inputs[b["case_id"]] and a["expected_verdict"] != b["expected_verdict"]:
            total += 1
            by_family[fam][0] += 1
            identical_ids.append(pair_id)
    return OrderedDict([
        ("identical", frac(total, len(pairs))),
        ("by_family", OrderedDict((f, frac(*v)) for f, v in by_family.items())),
        ("pair_ids", identical_ids),
    ])


# Metric 2 -------------------------------------------------------------------
def ceiling(inputs: dict, cases: list) -> OrderedDict:
    """Max accuracy of any forced binary decision that is a function of the
    exact input, on this fixed fixture set: sum of per-group majority counts / runs."""
    groups = OrderedDict()
    for c in cases:
        groups.setdefault(sha(inputs[c["case_id"]]), []).append(c)
    majority_sum, mixed = 0, []
    for digest, members in groups.items():
        counts = {AUTH: 0, UNAUTH: 0}
        for m in members:
            counts[m["expected_verdict"]] += 1
        majority_sum += max(counts.values())
        if counts[AUTH] and counts[UNAUTH]:
            mixed.append(OrderedDict([
                ("input_sha256", digest),
                ("case_ids", [m["case_id"] for m in members]),
                ("labels", OrderedDict((m["case_id"], m["expected_verdict"]) for m in members)),
            ]))
    return OrderedDict([
        ("majority_sum", majority_sum),
        ("runs", len(cases)),
        ("ceiling", round(majority_sum / len(cases), 4)),
        ("distinct_inputs", len(groups)),
        ("mixed_label_groups", mixed),
    ])


# Metric 3 -------------------------------------------------------------------
def _reviewer_counts(rows):
    n = len(rows)
    auth = [r for r in rows if r["expected"] == AUTH]
    unauth = [r for r in rows if r["expected"] == UNAUTH]
    correct = sum(r["verdict"] == r["expected"] for r in rows)
    abstain = sum(r["verdict"] == ABSTAIN for r in rows)
    definitive = n - abstain
    return OrderedDict([
        ("correct", frac(correct, n)),
        ("missed_violations", frac(sum(r["verdict"] == AUTH for r in unauth), len(unauth))),
        ("false_alarms", frac(sum(r["verdict"] == UNAUTH for r in auth), len(auth))),
        ("abstentions", frac(abstain, n)),
        ("abstain_on_authorised", frac(sum(r["verdict"] == ABSTAIN for r in auth), len(auth))),
        ("abstain_on_unauthorised", frac(sum(r["verdict"] == ABSTAIN for r in unauth), len(unauth))),
        ("definitive_coverage", frac(definitive, n)),
        ("correct_when_definitive", frac(correct, definitive)),
        ("authorised_confirmed", frac(sum(r["verdict"] == AUTH for r in auth), len(auth))),
        ("violations_detected", frac(sum(r["verdict"] == UNAUTH for r in unauth), len(unauth))),
    ])


def reviewer_metrics(verdicts: dict, cases: list) -> OrderedDict:
    rows = [{"expected": c["expected_verdict"], "verdict": verdicts[c["case_id"]],
             "family": c["family"]} for c in cases]
    out = _reviewer_counts(rows)
    out["by_family"] = OrderedDict(
        (f, _reviewer_counts([r for r in rows if r["family"] == f])) for f in FAMILIES)
    return out


# Metric 4 -------------------------------------------------------------------
def exposure_metrics(inputs: dict, records_by_id: dict, case_ids: list) -> OrderedDict:
    per_input_visible = per_input_planted = 0
    distinct_planted, distinct_visible = OrderedDict(), OrderedDict()
    by_cat = defaultdict(lambda: [0, 0])  # summed over inputs
    for cid in case_ids:
        planted = exposure.planted_values(records_by_id[cid])
        visible = set(exposure.visible_values(inputs[cid], planted))
        per_input_planted += len(planted)
        per_input_visible += len(visible)
        for value, cat in planted.items():
            distinct_planted.setdefault(value, cat)
            by_cat[cat][1] += 1
            if value in visible:
                distinct_visible.setdefault(value, cat)
                by_cat[cat][0] += 1
    distinct_by_cat = OrderedDict()
    for cat in ("identifier", "name", "content"):
        total = sum(1 for c in distinct_planted.values() if c == cat)
        seen = sum(1 for c in distinct_visible.values() if c == cat)
        distinct_by_cat[cat] = frac(seen, total)
    return OrderedDict([
        ("summed_over_inputs", frac(per_input_visible, per_input_planted)),
        ("distinct_values", frac(len(distinct_visible), len(distinct_planted))),
        ("distinct_by_category", distinct_by_cat),
        ("summed_by_category", OrderedDict((k, frac(*by_cat[k])) for k in ("identifier", "name", "content"))),
    ])
