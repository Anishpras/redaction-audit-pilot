"""Validation checks. Each returns a list of {"check", "ok", "detail"} dicts."""
from __future__ import annotations

import ast
import random
from collections import OrderedDict, defaultdict

from . import exposure, policy, views
from .fixtures import _shuffle_keys

FAMILY_RULES = {
    # family -> (paths that must differ in the pair, paths allowed to differ)
    "recipient": ({"events[1].recipient.id"},
                  {"events[1].recipient.id", "events[1].recipient.name"}),
    "document": ({"events[1].document.id"},
                 {"events[1].document.id", "events[1].document.title", "events[1].document.excerpt"}),
    "expiry": ({"events[0].expires_at"}, {"events[0].expires_at"}),
    "revocation": ({"events[0].revocation.status", "events[0].revocation.effective_at"},
                   {"events[0].revocation.status", "events[0].revocation.effective_at"}),
}
EXPECTED_FAILURE = {"recipient": ["recipient_mismatch"], "document": ["document_mismatch"],
                    "expiry": ["expired"], "revocation": ["revoked"]}
ALLOWED_REVIEWER_IMPORTS = {"json", "sys"}
FORBIDDEN_CALLS = {"open", "eval", "exec", "compile", "__import__", "input"}


def _result(check, ok, detail=""):
    return OrderedDict([("check", check), ("ok", bool(ok)), ("detail", detail)])


def _flatten(obj, prefix=""):
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten(v, "%s.%s" % (prefix, k) if prefix else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(_flatten(v, "%s[%d]" % (prefix, i)))
    else:
        out[prefix] = obj
    return out


def check_labels(records, manifest):
    """Hand-written label == trusted-fact oracle, for every core and sanity case."""
    out = []
    by_id = {r["case_id"]: r for r in records}
    for c in manifest["cases"]:
        got = policy.evaluate(by_id[c["case_id"]])
        ok = got["verdict"] == c["expected_verdict"]
        out.append(_result("label_matches_policy:%s" % c["case_id"], ok,
                           "label=%s oracle=%s failed=%s" % (c["expected_verdict"], got["verdict"], got["failed"])))
    return out


def check_sanity_labels(sanity_records, manifest):
    out = []
    by_id = {r["case_id"]: r for r in sanity_records}
    for c in manifest["sanity_cases"]:
        got = policy.evaluate(by_id[c["case_id"]])
        out.append(_result("sanity_label_matches_policy:%s" % c["case_id"],
                           got["verdict"] == c["expected_verdict"],
                           "label=%s oracle=%s" % (c["expected_verdict"], got["verdict"])))
    return out


def check_pairs(records, manifest):
    """Each pair: one authorised + one unauthorised; only the intended fact differs;
    the unauthorised case fails exactly the one intended condition."""
    out = []
    by_id = {r["case_id"]: r for r in records}
    pairs = defaultdict(list)
    for c in manifest["cases"]:
        pairs[c["pair_id"]].append(c)
    for pair_id in sorted(pairs):
        members = pairs[pair_id]
        roles = sorted(m["expected_verdict"] for m in members)
        fam = members[0]["family"]
        if roles != ["authorised", "unauthorised"]:
            out.append(_result("pair_roles:%s" % pair_id, False, str(roles)))
            continue
        auth = next(m for m in members if m["expected_verdict"] == "authorised")
        unauth = next(m for m in members if m["expected_verdict"] == "unauthorised")
        fa = _flatten({"events": by_id[auth["case_id"]]["events"]})
        fu = _flatten({"events": by_id[unauth["case_id"]]["events"]})
        diff = {p for p in set(fa) | set(fu) if fa.get(p, "<absent>") != fu.get(p, "<absent>")}
        must, allowed = FAMILY_RULES[fam]
        ok_diff = bool(diff & must) and diff <= allowed
        out.append(_result("pair_changes_only_intended_fact:%s" % pair_id, ok_diff,
                           "family=%s differing=%s" % (fam, sorted(diff))))
        fail_a = policy.evaluate(by_id[auth["case_id"]])["failed"]
        fail_u = policy.evaluate(by_id[unauth["case_id"]])["failed"]
        out.append(_result("pair_single_policy_difference:%s" % pair_id,
                           fail_a == [] and fail_u == EXPECTED_FAILURE[fam],
                           "auth_failed=%s unauth_failed=%s" % (fail_a, fail_u)))
    fam_counts = defaultdict(int)
    for pair_id, members in pairs.items():
        fam_counts[members[0]["family"]] += 1
    want = {"recipient": 4, "document": 2, "expiry": 2, "revocation": 2}
    out.append(_result("family_counts", dict(fam_counts) == want, str(dict(fam_counts))))
    return out


def check_boundary_coverage(records, manifest):
    """Boundary cases are checked on the pair and role that are meant to carry them."""
    by_id = {r["case_id"]: r for r in records}
    role_of = {(c["pair_id"], c["role"]): by_id[c["case_id"]]["events"] for c in manifest["cases"]}

    def ev(pair, role):
        return role_of[(pair, role)]
    g, s_ = ev("P07", "unauthorised")
    at_expiry = s_["time"] == g["expires_at"]
    g, s_ = ev("P09", "unauthorised")
    at_revocation = g["revocation"]["status"] == "revoked" and g["revocation"]["effective_at"] == s_["time"]
    at_grant = all(ev("P04", r)[1]["time"] == ev("P04", r)[0]["time"] for r in ("authorised", "unauthorised"))
    later_revocation = all(ev("P03", r)[0]["revocation"]["effective_at"] > ev("P03", r)[1]["time"]
                           for r in ("authorised", "unauthorised"))
    return [_result("boundary_P07_unauthorised_share_exactly_at_expiry", at_expiry),
            _result("boundary_P09_unauthorised_revocation_exactly_at_share", at_revocation),
            _result("boundary_P04_share_exactly_at_grant_time", at_grant),
            _result("boundary_P03_revocation_recorded_after_share", later_revocation)]


def check_planted_values(records):
    """Planted values must be distinguishable from retained, non-private text,
    so the exposure scanner cannot be triggered by masks, aliases or purposes."""
    out = []
    retained = set()
    for r in records:
        for e in r["events"]:
            retained.update(str(v) for k, v in _flatten(e).items()
                            if not any(k == ".".join(p) for p in views.PRIVATE_FIELDS))
    retained.update(views.UNIFORM_MASKS.values())
    retained.update(views.ALIAS_PREFIX.values())
    clashes = []
    for r in records:
        for value in exposure.planted_values(r):
            if any(value in t for t in retained):
                clashes.append(value)
            if not value.isascii() or '"' in value or "\\" in value:
                clashes.append("unsafe:" + value)
    out.append(_result("planted_values_distinct_from_retained_text", not clashes, str(clashes)))
    return out


REVIEWER_ALLOWED_ATTRIBUTES = {"get", "startswith", "stdin", "buffer", "read", "loads", "decode",
                               "stdout", "write", "dumps", "exit", "argv"}
REVIEWER_ALLOWED_BUILTINS = {"isinstance", "str", "all", "len", "int", "bool", "dict", "list"}


def check_reviewer_static(reviewer_path):
    """Allowlist: the reviewer may import only json and sys, use only listed attributes,
    call only its own functions and listed builtins, and touch no dunder names."""
    tree = ast.parse(open(reviewer_path, encoding="utf-8").read())
    defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    imports, bad_attrs, bad_calls, dunders = set(), set(), set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add((node.module or "").split(".")[0])
        elif isinstance(node, ast.Attribute):
            if node.attr not in REVIEWER_ALLOWED_ATTRIBUTES:
                bad_attrs.add(node.attr)
            if node.attr.startswith("__"):
                dunders.add(node.attr)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id not in defined | REVIEWER_ALLOWED_BUILTINS:
                bad_calls.add(node.func.id)
        elif isinstance(node, ast.Name) and node.id.startswith("__") and node.id != "__name__":
            dunders.add(node.id)
    return [_result("reviewer_imports_only_json_sys", imports <= ALLOWED_REVIEWER_IMPORTS, str(sorted(imports))),
            _result("reviewer_attribute_allowlist", not bad_attrs, str(sorted(bad_attrs))),
            _result("reviewer_call_allowlist", not bad_calls, str(sorted(bad_calls))),
            _result("reviewer_no_dunder_access", not dunders, str(sorted(dunders)))]


def check_inputs_carry_no_metadata(rendered, records, manifest):
    """No case/pair/run ids or label vocabulary in any reviewer input; only an event list."""
    forbidden = set()
    for r in records:
        forbidden.update([r["case_id"], r["run_id"]])
    for c in manifest["cases"]:
        forbidden.add(c["pair_id"])
    words = ["authorised", "unauthorised", "expected", "rationale", "pair_id", "case_id", "run_id", "family"]
    hits = []
    import json as _json
    for (view, cid), b in rendered.items():
        text = b.decode("ascii")
        for f in list(forbidden) + words:
            if f in text:
                hits.append("%s/%s:%s" % (view, cid, f))
        if set(_json.loads(text).keys()) != {"events"}:
            hits.append("%s/%s:top-level-keys" % (view, cid))
    return [_result("reviewer_inputs_exclude_ids_and_labels", not hits, str(hits[:10]))]


def check_canonical_determinism(records, seed):
    """Rendering twice gives identical bytes; so does a key-shuffled copy of each record."""
    rng = random.Random(seed + 1)
    unstable, order_sensitive = [], []
    for r in records:
        for view in views.VIEWS:
            if views.render(view, r) != views.render(view, r):
                unstable.append((view, r["case_id"]))
            if views.render(view, _shuffle_keys(r, rng)) != views.render(view, r):
                order_sensitive.append((view, r["case_id"]))
    return [_result("canonical_bytes_repeatable", not unstable, str(unstable)),
            _result("canonical_bytes_ignore_source_key_order", not order_sensitive, str(order_sensitive))]


def check_exposure_scanner(records):
    """Positive control: the full view exposes every planted value.
    Negative control: a string built only from retained text exposes none."""
    missing = []
    for r in records:
        planted = exposure.planted_values(r)
        seen = exposure.visible_values(views.render("A_full", r), planted)
        if len(seen) != len(planted):
            missing.append((r["case_id"], sorted(set(planted) - set(seen))))
    neg = exposure.visible_values(b'{"purpose":"case review","id":"[MASKED:recipient_id]"}',
                                  exposure.planted_values(records[0]))
    return [_result("scanner_finds_all_planted_values_in_full_view", not missing, str(missing)),
            _result("scanner_negative_control_empty", neg == [], str(neg))]


def check_full_view_matches_labels(verdicts_full, manifest):
    wrong = [(c["case_id"], c["expected_verdict"], verdicts_full[c["case_id"]])
             for c in manifest["cases"] if verdicts_full[c["case_id"]] != c["expected_verdict"]]
    return [_result("full_view_reviewer_matches_all_labels", not wrong,
                    "%d/%d match; mismatches=%s" % (len(manifest["cases"]) - len(wrong),
                                                    len(manifest["cases"]), wrong))]


def check_sanity(sanity_results, manifest):
    """Verdict unchanged in every view; expected views byte-identical to the base case."""
    out = []
    for c in manifest["sanity_cases"]:
        res = sanity_results[c["case_id"]]
        verdict_drift = [v for v, d in res.items() if d["verdict"] != d["base_verdict"]]
        should_match = set(c["expected_identical_views"])
        byte_mismatch = [v for v, d in res.items() if (v in should_match) != d["identical_to_base"]]
        out.append(_result("sanity_verdict_unchanged_all_views:%s" % c["case_id"], not verdict_drift,
                           "changed in %s" % verdict_drift))
        out.append(_result("sanity_byte_identity_as_expected:%s" % c["case_id"], not byte_mismatch,
                           "unexpected in %s" % byte_mismatch))
    return out


def check_shared_timeline_labels(records, cases):
    """The supplementary shared-timeline variant keeps every pair's intended label."""
    by_id = {r["case_id"]: r for r in records}
    wrong = [(c["pair_id"], c["role"], policy.evaluate(by_id[c["case_id"]])["verdict"])
             for c in cases if policy.evaluate(by_id[c["case_id"]])["verdict"] != c["expected_verdict"]]
    return [_result("shared_timeline_variant_labels_match_policy", not wrong, str(wrong))]


def check_metric_invariants(summary_views, n_runs, n_auth):
    """Cross-metric invariants. A stateless reviewer cannot beat the ceiling; outcome counts
    partition the runs; and in this matched-pair design the ceiling equals authorised runs plus
    unauthorised runs whose own input shows a failing condition (= violations detected)."""
    out = []
    for view, s in summary_views.items():
        m2, m3 = s["metric2_ceiling"], s["metric3_reviewer"]
        correct, abstain = m3["correct"]["n"], m3["abstentions"]["n"]
        missed, alarms = m3["missed_violations"]["n"], m3["false_alarms"]["n"]
        out.append(_result("invariant_correct_le_ceiling:%s" % view, correct <= m2["majority_sum"],
                           "correct=%d ceiling_sum=%d" % (correct, m2["majority_sum"])))
        out.append(_result("invariant_outcomes_partition_runs:%s" % view,
                           correct + abstain + missed + alarms == n_runs
                           and m3["definitive_coverage"]["n"] == n_runs - abstain))
        out.append(_result("invariant_ceiling_eq_auth_plus_detected:%s" % view,
                           m2["majority_sum"] == n_auth + m3["violations_detected"]["n"],
                           "ceiling_sum=%d auth=%d detected=%d" % (m2["majority_sum"], n_auth,
                                                                   m3["violations_detected"]["n"])))
    return out
