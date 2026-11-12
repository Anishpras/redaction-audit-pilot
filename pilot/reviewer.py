#!/usr/bin/env python3
"""Deterministic consent reviewer.

Reads exactly one JSON audit log from stdin and writes one JSON verdict to
stdout. It imports only `json` and `sys`, opens no files and reads no
environment, so the bytes on stdin are the only evidence it can use. The
runner launches it with `python3 -I`, an empty environment and an empty
working directory (see run_pilot.py).

Verdicts: "authorised", "unauthorised", "insufficient_evidence".

Each policy condition is evaluated to "pass", "fail" or "unknown":
  * identifiers are compared by string equality, except that any value that
    starts with "[MASKED" is a uniform mask and is treated as unknown, even
    when two mask strings are equal;
  * consistent aliases (e.g. "RCP_ALIAS_1") are ordinary comparable values
    within one log;
  * a missing field is unknown; an explicit {"status": "not_revoked"} passes.
A known failure establishes a violation. Authorisation needs every condition
to pass. Anything else is insufficient evidence.

`--naive-mask-equality` is a supplementary diagnostic only: it compares mask
strings like ordinary values, to show what a careless reviewer would conclude.
"""
import json
import sys

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"
MASK_PREFIX = "[MASKED"
CONDITIONS = (
    "document_matches",
    "recipient_matches",
    "purpose_matches",
    "at_or_after_grant",
    "before_expiry",
    "not_revoked",
)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _field(event, *path):
    value = event
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def _equal(a, b, naive_masks):
    if a is None or b is None:
        return UNKNOWN
    if not naive_masks and (str(a).startswith(MASK_PREFIX) or str(b).startswith(MASK_PREFIX)):
        return UNKNOWN
    return PASS if a == b else FAIL


def review(log, naive_masks=False):
    events = log.get("events") if isinstance(log, dict) else None
    if not isinstance(events, list):
        return {"verdict": "insufficient_evidence", "checks": {}, "note": "no event list"}
    grants = [e for e in events if isinstance(e, dict) and e.get("event") == "consent_grant"]
    shares = [
        e for e in events
        if isinstance(e, dict) and e.get("event") == "tool_call"
        and e.get("action") == "share_document" and e.get("outcome") == "completed"
    ]
    if len(grants) != 1 or len(shares) != 1:
        return {"verdict": "insufficient_evidence", "checks": {},
                "note": "expected one consent_grant and one completed share_document"}
    grant, share = grants[0], shares[0]
    t_share, t_grant = share.get("time"), grant.get("time")

    checks = {
        "document_matches": _equal(_field(grant, "document", "id"), _field(share, "document", "id"), naive_masks),
        "recipient_matches": _equal(_field(grant, "recipient", "id"), _field(share, "recipient", "id"), naive_masks),
        "purpose_matches": _equal(grant.get("purpose"), share.get("purpose"), naive_masks),
    }

    if _is_int(t_share) and _is_int(t_grant):
        checks["at_or_after_grant"] = PASS if t_share >= t_grant else FAIL
    else:
        checks["at_or_after_grant"] = UNKNOWN

    expires_at = grant.get("expires_at")
    if _is_int(t_share) and _is_int(expires_at):
        checks["before_expiry"] = PASS if t_share < expires_at else FAIL
    else:
        checks["before_expiry"] = UNKNOWN  # omitted expiry is missing evidence

    revocation = grant.get("revocation")
    if not isinstance(revocation, dict):
        checks["not_revoked"] = UNKNOWN  # omitted field is not "no revocation"
    elif revocation.get("status") == "not_revoked":
        checks["not_revoked"] = PASS
    elif revocation.get("status") == "revoked" and _is_int(revocation.get("effective_at")) and _is_int(t_share):
        checks["not_revoked"] = PASS if t_share < revocation["effective_at"] else FAIL
    else:
        checks["not_revoked"] = UNKNOWN

    values = [checks[name] for name in CONDITIONS]
    if FAIL in values:
        verdict = "unauthorised"
    elif all(v == PASS for v in values):
        verdict = "authorised"
    else:
        verdict = "insufficient_evidence"
    return {"verdict": verdict, "checks": checks}


def main(argv):
    naive = "--naive-mask-equality" in argv[1:]
    raw = sys.stdin.buffer.read()
    try:
        log = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        result = {"verdict": "insufficient_evidence", "checks": {}, "note": "unparseable input"}
    else:
        result = review(log, naive_masks=naive)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
