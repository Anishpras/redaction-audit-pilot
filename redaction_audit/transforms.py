"""Redaction transforms ("views") and canonical rendering.

A view is a named list of ops applied in order to one run's events:

  {"op": "keep"}                                     no change
  {"op": "mask", "fields": [...]}                    value -> "[MASKED:<category>]"
  {"op": "alias", "fields": [...]}                   per-run first-appearance aliases (ENTITY_1, ENTITY_2...)
  {"op": "pseudonym", "fields": [...], "scope": "run"|"event"|"global",
   "key": "...", "key_env": "VAR"}                   keyed HMAC-SHA256 pseudonyms; scope sets the
                                                     salt: per run, per event, or none
  {"op": "partial", "fields": [...], "keep_last": 4} keep the last N characters, replace the rest with "*"
  {"op": "drop", "fields": [...], "where": {...}}    delete fields (optionally only in matching events)
  {"op": "bucket", "fields": ["times"], "size": n}   floor integer values to multiples of n
  {"op": "rank", "fields": ["times"]}                replace integer values by their dense rank within the run
  {"op": "exec", "command": [...]}                   your own redactor: stdin {"events": [...]},
                                                     stdout {"events": [...], "declarations": {...}}

"fields" selectors: "private" (every private field), a category used in fields.json
("identifier", "name", "content" or your own), "times" (fields.json times), or an
explicit event-relative path. Selectors that match nothing are errors.

Every built-in op records a declaration per field path. Views render as canonical
JSON {"events": [...], "redaction": {...}}. The header is omitted if a view sets
"declare": false or nothing was declared. Run and case identifiers are never included.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import shlex
import subprocess
from collections import OrderedDict

from . import paths
from .spec import SpecError, hint

DEMO_KEY = "redaction-audit-demo-key-not-secret"


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def resolve(selectors, fields):
    """-> list of (path, category, entity) in a stable order."""
    private = fields.get("private", [])
    out, seen = [], set()

    def add(path, category, entity):
        if path not in seen:
            seen.add(path)
            out.append((path, category, entity))

    categories = {f["category"] for f in private}
    for s in selectors:
        if s == "private":
            for f in private:
                add(f["path"], f["category"], f.get("entity"))
        elif s in categories:
            for f in private:
                if f["category"] == s:
                    add(f["path"], f["category"], f.get("entity"))
        elif s == "times":
            for p in fields.get("times", []):
                add(p, "time", None)
        else:
            match = next((f for f in private if f["path"] == s), None)
            add(s, match["category"] if match else "value", match.get("entity") if match else None)
    return out


def _all_paths(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = "%s.%s" % (prefix, k) if prefix else k
            yield p
            yield from _all_paths(v, p)


def check_selectors(views, fields, logs):
    """Every selector must resolve to at least one field present in at least one case log."""
    present = set()
    for log in logs:
        for ev in log.get("events", []):
            present.update(_all_paths(ev))
    categories = sorted({f["category"] for f in fields.get("private", [])})
    problems = []
    for v in views["views"]:
        for j, op in enumerate(v.get("ops", [])):
            for sel in op.get("fields", []):
                targets = resolve([sel], fields)
                if not any(path in present for path, _, _ in targets):
                    kind = "selector" if sel in ("private", "times") or sel in categories else "field path"
                    problems.append("views %s ops[%d] (%s): %s %r matches no field in any case%s; selectors are "
                                    "'private', 'times', a category (%s) or an event-relative path"
                                    % (v["name"], j, op["op"], kind, sel,
                                       hint(sel, categories + ["private", "times"] + sorted(present)),
                                       ", ".join(categories) or "none defined"))
    for f in fields.get("private", []):
        if f["path"] not in present:
            problems.append("fields.private: path %r appears in no case%s" % (f["path"], hint(f["path"], sorted(present))))
    for t in fields.get("times", []):
        if t not in present:
            problems.append("fields.times: path %r appears in no case%s" % (t, hint(t, sorted(present))))
    if problems:
        raise SpecError(problems)


def _event_matches(event, where):
    return all(paths.get(event, k) == v for k, v in (where or {}).items())


def _entity_label(path, entity):
    return (entity or path).upper().replace(".", "_")


def _key(op):
    if op.get("key_env"):
        val = os.environ.get(op["key_env"])
        if not val:
            raise SpecError("pseudonym key_env %s is not set" % op["key_env"])
        return val
    return op.get("key", DEMO_KEY)


def _run_exec(op, events, base_dir):
    cmd = op["command"]
    argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    proc = subprocess.run(argv, input=canonical_bytes({"events": events}), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, cwd=base_dir or None, timeout=op.get("timeout", 60))
    if proc.returncode != 0:
        raise SpecError("exec transform %r failed: %s" % (argv, proc.stderr.decode(errors="replace")[:500]))
    try:
        out = json.loads(proc.stdout.decode("utf-8"), object_pairs_hook=OrderedDict)
    except ValueError:
        raise SpecError("exec transform %r did not print JSON" % (argv,))
    if not isinstance(out.get("events"), list):
        raise SpecError("exec transform %r must print {\"events\": [...]}" % (argv,))
    return out["events"], out.get("declarations") or {}


def apply_view(view, run_id, log, fields, base_dir=None):
    """Return the reviewer-facing dict for one run under one view."""
    events = copy.deepcopy(log["events"])
    decls = OrderedDict()
    for op in view.get("ops", []):
        kind = op["op"]
        targets = resolve(op.get("fields", []), fields)
        if kind == "keep":
            continue
        if kind == "mask":
            for path, cat, _ in targets:
                for ev in events:
                    if paths.has(ev, path):
                        paths.put(ev, path, "[MASKED:%s]" % cat)
                decls[path] = {"method": "mask"}
        elif kind == "alias":
            tables = {}
            for ev in events:  # fixed traversal: events in order, fields in selector order
                for path, _, entity in targets:
                    if paths.has(ev, path):
                        label = _entity_label(path, entity)
                        table = tables.setdefault(label, OrderedDict())
                        raw = json.dumps(paths.get(ev, path), sort_keys=True)
                        if raw not in table:
                            table[raw] = "%s_%d" % (label, len(table) + 1)
                        paths.put(ev, path, table[raw])
            for path, _, _ in targets:
                decls[path] = {"method": "alias", "scope": "run"}
        elif kind == "pseudonym":
            scope = op.get("scope", "run")
            key = _key(op).encode("utf-8")
            for i, ev in enumerate(events):
                salt = {"global": "", "run": str(run_id), "event": "%s#%d" % (run_id, i)}[scope]
                for path, _, entity in targets:
                    if paths.has(ev, path):
                        msg = "%s|%s|%s" % (salt, _entity_label(path, entity),
                                            json.dumps(paths.get(ev, path), sort_keys=True))
                        digest = hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
                        paths.put(ev, path, "PSN_" + digest)
            for path, _, _ in targets:
                decls[path] = {"method": "pseudonym", "scope": scope}
        elif kind == "partial":
            n, fill = op["keep_last"], op.get("fill", "*")
            for path, _, _ in targets:
                for ev in events:
                    v = paths.get(ev, path)
                    if v is not paths.MISSING and v is not None and not isinstance(v, (dict, list)):
                        text = str(v)
                        paths.put(ev, path, fill * max(len(text) - n, 0) + text[-n:])
                decls[path] = {"method": "partial", "keep_last": n}
        elif kind == "drop":
            for path, _, _ in targets:
                for ev in events:
                    if _event_matches(ev, op.get("where")):
                        paths.delete(ev, path)
                decls[path] = {"method": "drop"}
        elif kind == "bucket":
            size = op["size"]
            for path, _, _ in targets:
                for ev in events:
                    v = paths.get(ev, path)
                    if isinstance(v, (int, float)) and not isinstance(v, bool):
                        paths.put(ev, path, v - (v % size))
                decls[path] = {"method": "bucket", "size": size}
        elif kind == "rank":
            group = op.get("group", "times")
            values = sorted({paths.get(ev, p) for ev in events for p, _, _ in targets
                             if isinstance(paths.get(ev, p, None), (int, float))
                             and not isinstance(paths.get(ev, p), bool)})
            rank = {v: i + 1 for i, v in enumerate(values)}
            for path, _, _ in targets:
                for ev in events:
                    v = paths.get(ev, path)
                    if isinstance(v, (int, float)) and not isinstance(v, bool) and v in rank:
                        paths.put(ev, path, rank[v])
                decls[path] = {"method": "rank", "group": group}
        elif kind == "exec":
            events, extra = _run_exec(op, events, base_dir)
            for path, d in extra.items():
                decls[path] = d
    out = OrderedDict([("events", events)])
    if decls and view.get("declare", True):
        out["redaction"] = decls
    return out


def render(view, run_id, log, fields, base_dir=None) -> bytes:
    return canonical_bytes(apply_view(view, run_id, log, fields, base_dir))


def planted_values(log, fields):
    """Distinct values of private fields in an unredacted log -> category."""
    found = OrderedDict()
    for ev in log["events"]:
        for f in fields.get("private", []):
            v = paths.get(ev, f["path"])
            if v is not paths.MISSING and v is not None and not isinstance(v, (dict, list, bool)):
                found.setdefault(str(v), f["category"])
    return found


def visible_values(input_bytes, planted):
    out = []
    for value in planted:
        forms = {value.encode("utf-8"), json.dumps(value, ensure_ascii=True)[1:-1].encode("ascii")}
        if any(form in input_bytes for form in forms):
            out.append(value)
    return out
