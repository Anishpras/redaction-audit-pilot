"""Three-valued evaluation of a policy over one (possibly redacted) log.

The same function is the built-in reviewer and, on unredacted logs, the
reference that labels cases.

A redacted log may carry a ``redaction`` header: field path -> declaration, e.g.
    {"recipient.id": {"method": "pseudonym", "scope": "event"},
     "time": {"method": "bucket", "size": 10}}
In *declared* mode the reviewer uses these declarations, so it never compares
values in ways the transform has made meaningless:
  mask                -> unknown for every need
  alias / pseudonym   -> comparable for equality only within the declared scope
                         (run or global; event scope is not comparable across events)
  partial(keep_last)  -> different kept endings prove the values differ; equal endings prove nothing
  bucket(size n)      -> value v stands for [v, v+n); order is decided only when the
                         intervals cannot overlap
  rank(group g)       -> order and equality exact between fields of the same group
  drop                -> missing (unknown; presence conditions become unknown, not failed)
In *undeclared* mode the header is ignored and values are compared literally,
as a person or model unaware of the redaction would. Wrong verdicts that appear only
in that mode are reported as *unsafe*.

Order conditions compare numbers (integers or decimals). Convert timestamps to
numbers, for example epoch seconds, before auditing.
"""
from __future__ import annotations

from . import paths

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"
AUTH, UNAUTH, INSUFF = "authorised", "unauthorised", "insufficient_evidence"
INVERT = {PASS: FAIL, FAIL: PASS, UNKNOWN: UNKNOWN}


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def role_matches(policy, events):
    """role -> list of matching events."""
    out = {}
    for role, spec in policy["roles"].items():
        out[role] = [e for e in events if isinstance(e, dict)
                     and all(paths.get(e, k) == v for k, v in spec["where"].items())]
    return out


def select_roles(policy, events):
    """role -> the single matching event, or None if zero or several events match."""
    return {r: (hits[0] if len(hits) == 1 else None) for r, hits in role_matches(policy, events).items()}


def _read(roles, role_path, decls, declared):
    """-> (kind, value, declaration). kind: raw|missing|masked|pseudo|partial|bucket|rank|opaque|norole."""
    role, rel = role_path.split(".", 1)
    event = roles.get(role)
    if event is None:
        return ("norole", None, None)
    value = paths.get(event, rel)
    decl = decls.get(rel) if declared else None
    if value is paths.MISSING:
        return ("missing", None, decl)
    if not decl or decl.get("method") in (None, "keep"):
        return ("raw", value, None)
    kind = {"mask": "masked", "alias": "pseudo", "pseudonym": "pseudo", "partial": "partial",
            "bucket": "bucket", "rank": "rank", "drop": "missing"}.get(decl["method"], "opaque")
    return (kind, value, decl)


def _equality(a, b, same_event):
    ka, kb = a[0], b[0]
    blocked = ("norole", "missing", "masked", "opaque")
    if ka in blocked or kb in blocked:
        return UNKNOWN
    if ka == kb == "raw":
        return PASS if a[1] == b[1] else FAIL
    if ka == kb == "pseudo":
        sa, sb = a[2].get("scope", "run"), b[2].get("scope", "run")
        if sa != sb or (sa == "event" and not same_event):
            return UNKNOWN
        return PASS if a[1] == b[1] else FAIL
    if ka == kb == "partial":
        n = min(int(a[2].get("keep_last", 0)), int(b[2].get("keep_last", 0)))
        if n and str(a[1])[-n:] != str(b[1])[-n:]:
            return FAIL
        return UNKNOWN
    if ka == kb == "rank" and a[2].get("group") == b[2].get("group"):
        return PASS if a[1] == b[1] else FAIL
    if ka == kb == "bucket" and a[2].get("size") == b[2].get("size") and _is_num(a[1]) and _is_num(b[1]):
        if a[1] != b[1]:
            return FAIL
        return PASS if a[2].get("size") == 1 and isinstance(a[1], int) else UNKNOWN
    return UNKNOWN


def _interval(x):
    """-> (low, high, high_is_open) or None."""
    kind, value, decl = x
    if not _is_num(value):
        return None
    if kind == "raw":
        return (value, value, False)
    if kind == "bucket":
        size = decl.get("size", 1)
        if isinstance(value, int) and isinstance(size, int):
            return (value, value + size - 1, False)
        return (value, value + size, True)
    return None


def _order(a, op, b):
    """Decide `a op b` over numbers, possibly coarsened or ranked."""
    if a[0] == b[0] == "rank":
        if a[2].get("group") != b[2].get("group") or not (_is_num(a[1]) and _is_num(b[1])):
            return UNKNOWN
        a, b = ("raw", a[1], None), ("raw", b[1], None)
    if op in (">", ">="):  # a > b  <=>  b < a
        a, b, op = b, a, {">": "<", ">=": "<="}[op]
    ia, ib = _interval(a), _interval(b)
    if ia is None or ib is None:
        return UNKNOWN
    (la, ha, a_open), (lb, hb, b_open) = ia, ib
    if op == "<":
        if ha < lb or (a_open and ha <= lb):
            return PASS
        if la >= hb:
            return FAIL
    else:  # "<="
        if ha <= lb:
            return PASS
        if la > hb or (b_open and la >= hb):
            return FAIL
    return UNKNOWN


def _order_spec(roles, spec, decls, declared):
    return _order(_read(roles, spec["left"], decls, declared), spec["op"],
                  _read(roles, spec["right"], decls, declared))


def condition(roles, cond, decls, declared):
    need = cond["need"]
    if need == "equality":
        same = cond["left"].split(".", 1)[0] == cond["right"].split(".", 1)[0]
        r = _equality(_read(roles, cond["left"], decls, declared),
                      _read(roles, cond["right"], decls, declared), same)
        return INVERT[r] if cond.get("relation") == "different" else r
    if need == "order":
        return _order_spec(roles, cond, decls, declared)
    x = _read(roles, cond["field"], decls, declared)
    if need == "presence":
        if x[0] == "norole":
            return UNKNOWN
        if x[0] == "missing":
            declared_drop = x[2] is not None and x[2].get("method") == "drop"
            return UNKNOWN if declared_drop else FAIL
        return PASS
    if x[0] != "raw":
        return UNKNOWN
    if need == "raw_value":
        return PASS if x[1] in cond["allowed"] else FAIL
    if x[1] in cond["pass"]:  # explicit_state
        return PASS
    if x[1] in cond["fail"]:
        if "fail_only_if" not in cond:
            return FAIL
        return INVERT[_order_spec(roles, cond["fail_only_if"], decls, declared)]
    return UNKNOWN


def evaluate(policy, log, declared=True):
    """Return {"verdict": ..., "checks": {condition id: pass|fail|unknown}}."""
    events = log.get("events") if isinstance(log, dict) else None
    if not isinstance(events, list):
        return {"verdict": INSUFF, "checks": {c["id"]: UNKNOWN for c in policy["conditions"]}}
    decls = log.get("redaction") or {}
    roles = select_roles(policy, events)
    checks = {c["id"]: condition(roles, c, decls, declared) for c in policy["conditions"]}
    values = list(checks.values())
    if FAIL in values:
        verdict = UNAUTH
    elif all(v == PASS for v in values):
        verdict = AUTH
    else:
        verdict = INSUFF
    return {"verdict": verdict, "checks": checks}


def _paths_of(cond):
    if cond["need"] in ("equality", "order"):
        out = [cond["left"], cond["right"]]
    else:
        out = [cond["field"]]
    if "fail_only_if" in cond:
        out += [cond["fail_only_if"]["left"], cond["fail_only_if"]["right"]]
    return out


def explain(policy, log, cond):
    """Why a condition is undecidable on an unredacted log (for error messages)."""
    matches = role_matches(policy, log.get("events", []))
    reasons = []
    for role_path in _paths_of(cond):
        role, rel = role_path.split(".", 1)
        hits = matches.get(role, [])
        if len(hits) != 1:
            reasons.append("role %r matched %d events (needs exactly 1; check its 'where' filter %s)"
                           % (role, len(hits), dict(policy["roles"][role]["where"])))
            continue
        v = paths.get(hits[0], rel)
        if v is paths.MISSING:
            reasons.append("field %s is missing" % role_path)
        elif (cond["need"] == "order" or (cond["need"] == "explicit_state" and role_path in
                                          (cond.get("fail_only_if") or {}).values())) and not _is_num(v):
            reasons.append("field %s is %r (%s); order comparisons need numbers - convert timestamps to "
                           "epoch seconds and amounts to numbers" % (role_path, v, type(v).__name__))
    if cond["need"] == "explicit_state" and not reasons:
        v = paths.get(select_roles(policy, log["events"])[cond["field"].split(".", 1)[0]], cond["field"].split(".", 1)[1])
        reasons.append("value %r of %s is in neither 'pass' %s nor 'fail' %s" % (v, cond["field"], cond["pass"], cond["fail"]))
    return "; ".join(dict.fromkeys(reasons)) or "undecidable"


def reference(policy, log):
    """Label an unredacted log. Returns (verdict, failed condition ids); raises ValueError with a
    precise reason if any condition cannot be decided (the case lacks evidence it should carry)."""
    out = evaluate(policy, log, declared=True)
    unknown = [c for c in policy["conditions"] if out["checks"][c["id"]] == UNKNOWN]
    if unknown:
        raise ValueError("undecidable on the unredacted log: " +
                         "; ".join("%s (%s)" % (c["id"], explain(policy, log, c)) for c in unknown))
    return out["verdict"], [k for k, v in out["checks"].items() if v == FAIL]
