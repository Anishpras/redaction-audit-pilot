"""Cases: explicit matched pairs, generated matched pairs, or both.

cases.jsonl holds one JSON object per line. Two kinds of line can be mixed freely:

Explicit (has "label"): a hand-written matched pair member
  {"case_id": "...", "pair_id": "...", "family": "...", "label": "authorised"|"unauthorised",
   "log": {"events": [...]}}
  Each pair_id needs exactly one authorised and one unauthorised case.

Base (no "label"): an authorised log from which violations are generated
  {"case_id": "...", "log": {"events": [...]}, "decoys": {"pool": [...] or value}}   # decoys optional
  For every base and every policy condition, the toolkit generates an unauthorised partner by a
  *mutation* that makes exactly that condition fail. Defaults sit on the boundary (for example
  expiry set equal to the action time) and change values in the same format (the first letter
  or digit changes, so the ending is kept, which exposes keep-last-N redaction). Override per
  condition in policy.json with "mutate" (one violation) or "mutations" (several), e.g.
    "mutate": [{"set": {"action.recipient": {"decoy": "recipients"}}}]
    "mutations": [[{"set": {"authority.expires_at": {"copy": "action.time"}}}],
                  [{"set": {"authority.expires_at": {"add": ["action.time", -3600]}}}]]
  Value expressions: a literal, {"copy": path}, {"add": [path, number]},
  {"different_from": path}, {"decoy": pool} (case "decoys" first, then policy "decoys"),
  {"literal": value}.

Every case is checked against the reference evaluation of its unredacted log, and every
generated partner must fail exactly its target condition.
"""
from __future__ import annotations

import copy
import hashlib
from collections import OrderedDict

from . import evaluate, paths
from .spec import SpecError

TRUE_AT_BOUNDARY = {  # make "L op R" true by moving one side onto the boundary
    ("left", "<"): ("right", -1), ("left", "<="): ("right", 0),
    ("left", ">"): ("right", 1), ("left", ">="): ("right", 0),
    ("right", "<"): ("left", 1), ("right", "<="): ("left", 0),
    ("right", ">"): ("left", -1), ("right", ">="): ("left", 0),
}
FALSE_AT_BOUNDARY = {  # make "L op R" false by moving one side onto the boundary
    ("left", "<"): ("right", 0), ("left", "<="): ("right", 1),
    ("left", ">"): ("right", 0), ("left", ">="): ("right", -1),
    ("right", "<"): ("left", 0), ("right", "<="): ("left", -1),
    ("right", ">"): ("left", 0), ("right", ">="): ("left", 1),
}


def _opaque(*parts):
    return "run-" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:10]


def _role(path):
    return path.split(".", 1)[0]


def perturb(value):
    """A different value in the same format: change the first letter or digit (keeps the ending)."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 1
    text = str(value)
    for i, ch in enumerate(text):
        if ch.isdigit():
            return text[:i] + str((int(ch) + 1) % 10) + text[i + 1:]
        if ch.isascii() and ch.isalpha():
            base = ord("a") if ch.islower() else ord("A")
            return text[:i] + chr((ord(ch) - base + 1) % 26 + base) + text[i + 1:]
    return text + "-x"


def _side_to_mutate(policy, spec):
    """Prefer changing the evidence side, not the audited action (the 'subject' role)."""
    subject = policy.get("subject")
    if subject and _role(spec["right"]) == subject and _role(spec["left"]) != subject:
        return "left"
    return "right"


def default_mutation(policy, cond):
    need = cond["need"]
    subject = policy.get("subject")
    if need == "equality":
        # change what the audited action did (the subject side) when there is one
        side = "left" if subject and _role(cond["left"]) == subject and _role(cond["right"]) != subject else "right"
        other = "right" if side == "left" else "left"
        if cond.get("relation") == "different":
            return [{"set": {cond[side]: {"copy": cond[other]}}}]
        return [{"set": {cond[side]: {"different_from": cond[side]}}}]
    if need == "order":
        side = _side_to_mutate(policy, cond)
        other, delta = FALSE_AT_BOUNDARY[(side, cond["op"])]
        return [{"set": {cond[side]: {"add": [cond[other], delta]}}}]
    if need == "explicit_state":
        ops = [{"set": {cond["field"]: cond["fail"][0]}}]
        if "fail_only_if" in cond:
            spec = cond["fail_only_if"]
            side = _side_to_mutate(policy, spec)
            other, delta = TRUE_AT_BOUNDARY[(side, spec["op"])]
            ops.append({"set": {spec[side]: {"add": [spec[other], delta]}}})
        return ops
    if need == "raw_value":
        return [{"set": {cond["field"]: {"different_from": cond["field"]}}}]
    return [{"delete": [cond["field"]]}]  # presence


def mutation_variants(policy, cond):
    if cond.get("mutations"):
        return cond["mutations"]
    return [cond.get("mutate") or default_mutation(policy, cond)]


def _get(roles, role_path):
    role, rel = role_path.split(".", 1)
    v = paths.get(roles[role], rel) if roles.get(role) is not None else paths.MISSING
    if v is paths.MISSING:
        raise SpecError("mutation refers to missing field %s" % role_path)
    return v


def _value(expr, roles, policy, current, case_decoys):
    if not isinstance(expr, dict):
        return copy.deepcopy(expr)
    if "literal" in expr:
        return copy.deepcopy(expr["literal"])
    if "copy" in expr:
        return copy.deepcopy(_get(roles, expr["copy"]))
    if "add" in expr:
        base = _get(roles, expr["add"][0])
        if not evaluate._is_num(base):
            raise SpecError("mutation 'add' needs a number at %s, found %r" % (expr["add"][0], base))
        return base + expr["add"][1]
    if "different_from" in expr:
        return perturb(_get(roles, expr["different_from"]))
    if "decoy" in expr:
        name = expr["decoy"]
        pool = (case_decoys or {}).get(name, policy.get("decoys", {}).get(name))
        if pool is None:
            raise SpecError("decoy %r is defined neither in the case's 'decoys' nor in policy.decoys" % name)
        if not isinstance(pool, list):
            return copy.deepcopy(pool)
        for item in pool:
            if item != current:
                return copy.deepcopy(item)
        raise SpecError("decoy pool %r has no value different from the current one" % name)
    return copy.deepcopy(expr)


def mutate(policy, cond, log, ops=None, case_decoys=None):
    out = copy.deepcopy(log)
    roles = evaluate.select_roles(policy, out["events"])
    for op in ops if ops is not None else mutation_variants(policy, cond)[0]:
        for role_path, expr in op.get("set", {}).items():
            role, rel = role_path.split(".", 1)
            if roles.get(role) is None:
                raise SpecError("mutation for %s: role %r not found exactly once" % (cond["id"], role))
            current = paths.get(roles[role], rel, None)
            paths.put(roles[role], rel, _value(expr, roles, policy, current, case_decoys))
        for role_path in op.get("delete", []):
            role, rel = role_path.split(".", 1)
            if roles.get(role) is not None:
                paths.delete(roles[role], rel)
    return out


def _load_explicit(policy, records, runs, pairs, problems):
    groups = OrderedDict()
    for r in records:
        cid = r.get("case_id")
        if not cid or cid in runs:
            problems.append("case_id missing or duplicated: %r" % cid)
            continue
        if r["label"] not in (evaluate.AUTH, evaluate.UNAUTH):
            problems.append("%s: label must be 'authorised' or 'unauthorised'" % cid)
            continue
        runs[cid] = {"case_id": cid, "label": r["label"], "log": r["log"]}
        groups.setdefault(r.get("pair_id", cid), []).append(r)
        try:
            verdict, failed = evaluate.reference(policy, r["log"])
        except ValueError as exc:
            problems.append("%s: %s" % (cid, exc))
            continue
        if verdict != r["label"]:
            problems.append("%s: labelled %s but the policy gives %s (failed: %s)"
                            % (cid, r["label"], verdict, ", ".join(failed) or "none"))
        runs[cid]["failed"] = failed
    for pid, members in groups.items():
        labels = sorted(m["label"] for m in members)
        if labels != [evaluate.AUTH, evaluate.UNAUTH]:
            problems.append("pair %s: needs exactly one authorised and one unauthorised case" % pid)
            continue
        a = next(m for m in members if m["label"] == evaluate.AUTH)
        u = next(m for m in members if m["label"] == evaluate.UNAUTH)
        failed = runs[u["case_id"]].get("failed", [])
        target = u.get("target") or (failed[0] if len(failed) == 1 else None)
        pairs.append({"pair_id": pid, "family": a.get("family", u.get("family", target or pid)),
                      "target": target, "auth": a["case_id"], "unauth": u["case_id"]})


def _load_generated(policy, records, runs, pairs, problems):
    bases = []
    for r in records:
        cid = r.get("case_id")
        if not cid or cid in runs:
            problems.append("case_id missing or duplicated: %r" % cid)
            continue
        try:
            verdict, failed = evaluate.reference(policy, r["log"])
        except ValueError as exc:
            problems.append("base %s: %s" % (cid, exc))
            continue
        if verdict != evaluate.AUTH:
            problems.append("base %s must be authorised, but fails: %s" % (cid, ", ".join(failed)))
            continue
        runs[cid] = {"case_id": cid, "label": evaluate.AUTH, "log": r["log"]}
        bases.append((cid, r.get("decoys")))
    if problems:
        return
    for base_id, decoys in bases:
        for cond in policy["conditions"]:
            variants = mutation_variants(policy, cond)
            for k, ops in enumerate(variants, 1):
                tag = cond["id"] if len(variants) == 1 else "%s#%d" % (cond["id"], k)
                try:
                    log = mutate(policy, cond, runs[base_id]["log"], ops, decoys)
                    verdict, failed = evaluate.reference(policy, log)
                except (SpecError, ValueError) as exc:
                    problems.append("base %s, condition %s: %s" % (base_id, tag, exc))
                    continue
                if failed != [cond["id"]]:
                    problems.append("base %s, condition %s: the mutation fails %s instead of exactly %s; "
                                    "give this condition an explicit 'mutate' in policy.json"
                                    % (base_id, tag, ", ".join(failed) or "nothing", cond["id"]))
                    continue
                rid = _opaque(base_id, tag)
                runs[rid] = {"case_id": rid, "label": evaluate.UNAUTH, "log": log, "base": base_id}
                pairs.append({"pair_id": "%s~%s" % (base_id, tag), "family": cond["id"],
                              "target": cond["id"], "auth": base_id, "unauth": rid})


def load(policy, records):
    """-> (runs, pairs, mode). runs: OrderedDict run_id -> {case_id, label, log};
    pairs: list of {pair_id, family, target, auth, unauth} (auth/unauth are run ids)."""
    if not records:
        raise SpecError("cases file is empty")
    explicit = [r for r in records if "label" in r]
    bases = [r for r in records if "label" not in r]
    problems, runs, pairs = [], OrderedDict(), []
    for i, r in enumerate(records):
        if not isinstance(r.get("log"), dict) or not isinstance(r["log"].get("events"), list):
            problems.append("case %s: needs \"log\": {\"events\": [...]}" % r.get("case_id", "#%d" % (i + 1)))
    if problems:
        raise SpecError(problems)
    if explicit:
        _load_explicit(policy, explicit, runs, pairs, problems)
    if bases:
        _load_generated(policy, bases, runs, pairs, problems)
    if problems:
        raise SpecError(problems)
    mode = "mixed" if explicit and bases else ("explicit" if explicit else "generated")
    return runs, pairs, mode
