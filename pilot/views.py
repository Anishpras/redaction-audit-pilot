"""Reviewer-facing views, all generated from the same underlying record.

The underlying record is {"case_id", "run_id", "events": [...]}. Every view
drops case_id and run_id and keeps the event list in its recorded order.
The exact bytes passed to the reviewer are `render(view_fn, record)`:
canonical JSON with sorted keys, no insignificant whitespace, ASCII only.

Private fields (decided before the main run; PROTOCOL.md section 4):
  identifiers : document.id, recipient.id
  names       : document.title, recipient.name
  contents    : document.excerpt, message
Retained in every view because the consent rule needs them: event type,
action, outcome, actor role, purpose, all timestamps, expiry, revocation.
"""
from __future__ import annotations

import copy
import json
from collections import OrderedDict

# (path inside an event) -> category. Order is the fixed traversal order.
PRIVATE_FIELDS = OrderedDict([
    (("document", "id"), "identifier"),
    (("recipient", "id"), "identifier"),
    (("document", "title"), "name"),
    (("recipient", "name"), "name"),
    (("document", "excerpt"), "content"),
    (("message",), "content"),
])

UNIFORM_MASKS = {
    ("document", "id"): "[MASKED:document_id]",
    ("recipient", "id"): "[MASKED:recipient_id]",
    ("document", "title"): "[MASKED:name]",
    ("recipient", "name"): "[MASKED:name]",
    ("document", "excerpt"): "[MASKED:content]",
    ("message",): "[MASKED:content]",
}
TEXT_FIELDS = [p for p, cat in PRIVATE_FIELDS.items() if cat in ("name", "content")]
ALIAS_PREFIX = {"document": "DOC_ALIAS_", "recipient": "RCP_ALIAS_"}
ALIAS_KINDS = ("document", "recipient")  # within an event: document before recipient


def canonical_bytes(obj) -> bytes:
    """Stable serialisation: sorted keys, list order preserved, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _has(obj, path):
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return False
        obj = obj[key]
    return True


def _get(obj, path):
    for key in path:
        obj = obj[key]
    return obj


def _set(obj, path, value):
    for key in path[:-1]:
        obj = obj[key]
    obj[path[-1]] = value


def _reviewer_copy(record):
    """Drop everything except the event list (no case_id, run_id, labels)."""
    return {"events": copy.deepcopy(record["events"])}


def _mask_text(log):
    for event in log["events"]:
        for path in TEXT_FIELDS:
            if _has(event, path):
                _set(event, path, UNIFORM_MASKS[path])


def view_full(record):
    """A. Full evidence: synthetic raw identifiers, names, contents and all facts."""
    return _reviewer_copy(record)


def view_uniform_mask(record):
    """B. Uniform masking: one constant mask per field type."""
    log = _reviewer_copy(record)
    for event in log["events"]:
        for path in PRIVATE_FIELDS:
            if _has(event, path):
                _set(event, path, UNIFORM_MASKS[path])
    return log


def alias_table(record):
    """Deterministic per-run aliases by first appearance.

    Traversal: events in recorded order; inside each event, document.id then
    recipient.id. Separate counters per type, reset for every run.
    """
    tables = {kind: OrderedDict() for kind in ALIAS_KINDS}
    for event in record["events"]:
        for kind in ALIAS_KINDS:
            if _has(event, (kind, "id")):
                raw = _get(event, (kind, "id"))
                if raw not in tables[kind]:
                    tables[kind][raw] = "%s%d" % (ALIAS_PREFIX[kind], len(tables[kind]) + 1)
    return tables


def view_alias(record):
    """C. Consistent aliases: B's text masking plus equality-preserving ids."""
    log = _reviewer_copy(record)
    tables = alias_table(record)
    for event in log["events"]:
        for kind in ALIAS_KINDS:
            if _has(event, (kind, "id")):
                _set(event, (kind, "id"), tables[kind][_get(event, (kind, "id"))])
    _mask_text(log)
    return log


def _drop_from_grant(log, key):
    for event in log["events"]:
        if event.get("event") == "consent_grant":
            event.pop(key, None)
    return log


def view_alias_no_expiry(record):
    """C ablation: omit the grant's expiry."""
    return _drop_from_grant(view_alias(record), "expires_at")


def view_alias_no_revocation(record):
    """C ablation: omit the grant's revocation evidence (including 'not_revoked')."""
    return _drop_from_grant(view_alias(record), "revocation")


CORE_VIEWS = OrderedDict([
    ("A_full", view_full),
    ("B_uniform_mask", view_uniform_mask),
    ("C_alias", view_alias),
])
ABLATION_VIEWS = OrderedDict([
    ("C_no_expiry", view_alias_no_expiry),
    ("C_no_revocation", view_alias_no_revocation),
])
VIEWS = OrderedDict(list(CORE_VIEWS.items()) + list(ABLATION_VIEWS.items()))


def render(view_name: str, record: dict) -> bytes:
    """The exact reviewer input for one view of one record."""
    return canonical_bytes(VIEWS[view_name](record))
