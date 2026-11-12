"""Dotted-path helpers over nested dicts ("attributes.customer_id").

Keys containing dots are not supported. Lists are treated as leaf values.
"""
from __future__ import annotations

MISSING = object()


def parts(path: str):
    return path.split(".") if path else []


def get(obj, path: str, default=MISSING):
    cur = obj
    for key in parts(path):
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def has(obj, path: str) -> bool:
    return get(obj, path) is not MISSING


def put(obj, path: str, value) -> None:
    keys = parts(path)
    cur = obj
    for key in keys[:-1]:
        nxt = cur.get(key)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[key] = nxt
        cur = nxt
    cur[keys[-1]] = value


def delete(obj, path: str) -> bool:
    keys = parts(path)
    cur = obj
    for key in keys[:-1]:
        if not isinstance(cur, dict) or key not in cur:
            return False
        cur = cur[key]
    if isinstance(cur, dict) and keys[-1] in cur:
        del cur[keys[-1]]
        return True
    return False


def leaves(obj, prefix=""):
    """Yield (path, value) for every non-dict value."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield from leaves(value, "%s.%s" % (prefix, key) if prefix else key)
    else:
        yield prefix, obj
