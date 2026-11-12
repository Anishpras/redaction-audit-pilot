"""Direct-exposure scanner for planted values.

Planted values are the values of the private fields (views.PRIVATE_FIELDS) in
the underlying record. A value counts as visible if its exact text, or its
JSON-escaped form, occurs anywhere in the exact reviewer input bytes.

Scope: exact-substring exposure of the planted strings only. It does not
detect partial fragments (e.g. a surname alone), transformed values, or
inference from retained context such as purposes and timestamps.
"""
from __future__ import annotations

import json
from collections import OrderedDict

from . import views


def planted_values(record: dict) -> "OrderedDict[str, str]":
    """Distinct planted values in one record -> category."""
    found = OrderedDict()
    for event in record["events"]:
        for path, category in views.PRIVATE_FIELDS.items():
            if views._has(event, path):
                value = views._get(event, path)
                found.setdefault(value, category)
    return found


def _forms(value: str):
    escaped = json.dumps(value, ensure_ascii=True)[1:-1]
    return {value.encode("utf-8"), escaped.encode("ascii")}


def visible_values(input_bytes: bytes, planted) -> list:
    return [v for v in planted if any(form in input_bytes for form in _forms(v))]
