"""Trusted-fact consent oracle.

This module evaluates the written consent rule on the *underlying* record, where
every fact is present and trusted. It exists only to check the hand-written
labels in the manifest. The reviewer (pilot/reviewer.py) is a separate
implementation that only ever sees one rendered view and must cope with
masked or missing facts.

Consent rule (see PROTOCOL.md section 2). A completed share is authorised iff
  1. grant and share match on document id, recipient id and purpose;
  2. grant.time <= share.time < grant.expires_at;
  3. no revocation with effective_at <= share.time.
Times are simulated integers. Expiry and revocation take effect at their
recorded time, including when equal to the share time.
"""
from __future__ import annotations

AUTHORISED = "authorised"
UNAUTHORISED = "unauthorised"


def _single(events, predicate, what):
    found = [e for e in events if predicate(e)]
    if len(found) != 1:
        raise ValueError("expected exactly one %s, found %d" % (what, len(found)))
    return found[0]


def evaluate(record: dict) -> dict:
    """Return {"verdict": ..., "failed": [...]} for a complete underlying record.

    Raises ValueError / KeyError if the record is incomplete: fixtures must
    carry every fact, so a missing fact here is a fixture bug, not "unknown".
    """
    events = record["events"]
    grant = _single(events, lambda e: e["event"] == "consent_grant", "consent_grant")
    share = _single(
        events,
        lambda e: e["event"] == "tool_call" and e["action"] == "share_document",
        "share_document call",
    )
    if share["outcome"] != "completed":
        raise ValueError("pilot fixtures audit completed shares only")

    t = share["time"]
    failed = []
    if share["document"]["id"] != grant["document"]["id"]:
        failed.append("document_mismatch")
    if share["recipient"]["id"] != grant["recipient"]["id"]:
        failed.append("recipient_mismatch")
    if share["purpose"] != grant["purpose"]:
        failed.append("purpose_mismatch")
    if t < grant["time"]:
        failed.append("before_grant")
    if t >= grant["expires_at"]:
        failed.append("expired")
    revocation = grant["revocation"]
    if revocation["status"] == "revoked":
        if revocation["effective_at"] <= t:
            failed.append("revoked")
    elif revocation["status"] != "not_revoked":
        raise ValueError("unknown revocation status %r" % revocation["status"])

    return {"verdict": UNAUTHORISED if failed else AUTHORISED, "failed": failed}
