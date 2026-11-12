"""Loading and strict checking of the four input files.

Every problem is collected and reported at once, with a "did you mean" hint where possible.
Unknown keys are errors, because a silently ignored key can invert a rule.
"""
from __future__ import annotations

import difflib
import json
from collections import OrderedDict

NEEDS = ("equality", "order", "explicit_state", "raw_value", "presence")
ORDER_OPS = ("<", "<=", ">", ">=")
RELATIONS = ("same", "different")
BUILTIN_OPS = ("keep", "mask", "alias", "pseudonym", "partial", "drop", "bucket", "rank", "exec")
SCOPES = ("run", "event", "global")

POLICY_KEYS = {"name", "description", "subject", "roles", "conditions", "decoys", "notes"}
ROLE_KEYS = {"where", "note"}
COND_COMMON = {"id", "need", "mutate", "mutations", "note", "description"}
COND_KEYS = {
    "equality": COND_COMMON | {"left", "right", "relation"},
    "order": COND_COMMON | {"left", "op", "right"},
    "explicit_state": COND_COMMON | {"field", "pass", "fail", "fail_only_if"},
    "raw_value": COND_COMMON | {"field", "allowed"},
    "presence": COND_COMMON | {"field"},
}
ORDER_KEYS = {"left", "op", "right"}
FIELDS_KEYS = {"private", "times", "note"}
PRIVATE_KEYS = {"path", "category", "entity", "note"}
VIEWS_KEYS = {"views", "note"}
VIEW_KEYS = {"name", "role", "note", "ops", "declare"}
OP_COMMON = {"op", "fields", "where", "note"}
OP_KEYS = {
    "keep": {"op", "note"},
    "mask": OP_COMMON,
    "alias": OP_COMMON | {"scope"},
    "pseudonym": OP_COMMON | {"scope", "key", "key_env"},
    "partial": OP_COMMON | {"keep_last", "fill"},
    "drop": OP_COMMON,
    "bucket": OP_COMMON | {"size"},
    "rank": OP_COMMON | {"group"},
    "exec": {"op", "command", "timeout", "note"},
}


class SpecError(Exception):
    def __init__(self, problems):
        self.problems = list(problems) if isinstance(problems, (list, tuple)) else [problems]
        super().__init__("\n".join(self.problems))


def hint(word, choices):
    close = difflib.get_close_matches(str(word), [str(c) for c in choices], n=1, cutoff=0.6)
    return " (did you mean %r?)" % close[0] if close else ""


def _unknown_keys(obj, allowed, where, problems):
    if not isinstance(obj, dict):
        problems.append("%s: must be a JSON object" % where)
        return
    for key in obj:
        if key not in allowed:
            problems.append("%s: unknown key %r%s; allowed: %s"
                            % (where, key, hint(key, allowed), ", ".join(sorted(allowed))))


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh, object_pairs_hook=OrderedDict)
    except ValueError as exc:
        raise SpecError("%s: invalid JSON (%s)" % (path, exc))
    except OSError as exc:
        raise SpecError("%s: cannot read (%s)" % (path, exc))


def load_jsonl(path):
    out = []
    try:
        fh = open(path, encoding="utf-8")
    except OSError as exc:
        raise SpecError("%s: cannot read (%s)" % (path, exc))
    with fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                out.append(json.loads(line, object_pairs_hook=OrderedDict))
            except ValueError as exc:
                raise SpecError("%s line %d: invalid JSON (%s)" % (path, n, exc))
    return out


def split_role_path(policy, role_path, where, problems):
    if not isinstance(role_path, str) or "." not in role_path:
        problems.append("%s: %r must be '<role>.<field path>'" % (where, role_path))
        return None, None
    role, rel = role_path.split(".", 1)
    roles = policy.get("roles", {}) if isinstance(policy.get("roles"), dict) else {}
    if role not in roles:
        problems.append("%s: unknown role %r%s (roles: %s)" % (where, role, hint(role, roles), ", ".join(roles)))
        return None, None
    return role, rel


def _check_order(policy, spec, where, problems):
    if not isinstance(spec, dict):
        problems.append("%s: must be an object with left/op/right" % where)
        return
    for key in ("left", "right"):
        split_role_path(policy, spec.get(key), "%s.%s" % (where, key), problems)
    if spec.get("op") not in ORDER_OPS:
        problems.append("%s.op: %r must be one of %s" % (where, spec.get("op"), ", ".join(ORDER_OPS)))


def _check_mutation_list(policy, ops, where, problems):
    if not isinstance(ops, list):
        problems.append("%s: must be a list of {set: ...} / {delete: [...]} steps" % where)
        return
    for j, op in enumerate(ops):
        _unknown_keys(op, {"set", "delete"}, "%s[%d]" % (where, j), problems)
        for rp in (op.get("set") or {}) if isinstance(op, dict) else {}:
            split_role_path(policy, rp, "%s[%d].set" % (where, j), problems)
        for rp in (op.get("delete") or []) if isinstance(op, dict) else []:
            split_role_path(policy, rp, "%s[%d].delete" % (where, j), problems)


def check_policy(policy):
    problems = []
    _unknown_keys(policy, POLICY_KEYS, "policy", problems)
    roles = policy.get("roles")
    if not isinstance(roles, dict) or not roles:
        problems.append("policy.roles: required, e.g. {\"action\": {\"where\": {\"event\": \"tool_call\"}}}")
        roles = {}
    for name, spec in roles.items():
        _unknown_keys(spec, ROLE_KEYS, "policy.roles.%s" % name, problems)
        if not isinstance(spec, dict) or not isinstance(spec.get("where"), dict) or not spec["where"]:
            problems.append("policy.roles.%s.where: required non-empty object of field path -> value" % name)
    subject = policy.get("subject")
    if subject is not None and subject not in roles:
        problems.append("policy.subject: %r is not a role%s" % (subject, hint(subject, roles)))
    conds = policy.get("conditions")
    if not isinstance(conds, list) or not conds:
        problems.append("policy.conditions: required non-empty list")
        conds = []
    seen = set()
    for i, c in enumerate(conds):
        where = "policy.conditions[%d]" % i
        if not isinstance(c, dict):
            problems.append("%s: must be an object" % where)
            continue
        cid = c.get("id")
        where = "policy.conditions[%d] (%s)" % (i, cid)
        if not cid or cid in seen:
            problems.append("%s.id: required and unique" % where)
        seen.add(cid)
        need = c.get("need")
        if need not in NEEDS:
            problems.append("%s.need: %r must be one of %s%s" % (where, need, ", ".join(NEEDS), hint(need, NEEDS)))
            continue
        _unknown_keys(c, COND_KEYS[need], where, problems)
        if need == "equality":
            for key in ("left", "right"):
                split_role_path(policy, c.get(key), "%s.%s" % (where, key), problems)
            if c.get("relation", "same") not in RELATIONS:
                problems.append("%s.relation: must be 'same' (default) or 'different'" % where)
        elif need == "order":
            _check_order(policy, c, where, problems)
        else:
            split_role_path(policy, c.get("field"), "%s.field" % where, problems)
        if need == "explicit_state":
            if not c.get("pass") or not c.get("fail"):
                problems.append("%s: explicit_state needs non-empty 'pass' and 'fail' value lists" % where)
            if "fail_only_if" in c:
                _unknown_keys(c["fail_only_if"], ORDER_KEYS, where + ".fail_only_if", problems)
                _check_order(policy, c["fail_only_if"], where + ".fail_only_if", problems)
        if need == "raw_value" and not isinstance(c.get("allowed"), list):
            problems.append("%s.allowed: raw_value needs a list of allowed values" % where)
        if "mutate" in c and "mutations" in c:
            problems.append("%s: use either 'mutate' (one violation) or 'mutations' (several), not both" % where)
        if "mutate" in c:
            _check_mutation_list(policy, c["mutate"], where + ".mutate", problems)
        if "mutations" in c:
            if not isinstance(c["mutations"], list) or not c["mutations"]:
                problems.append("%s.mutations: must be a non-empty list of mutation lists" % where)
            else:
                for k, m in enumerate(c["mutations"]):
                    _check_mutation_list(policy, m, "%s.mutations[%d]" % (where, k), problems)
    if problems:
        raise SpecError(problems)
    return policy


def check_fields(fields):
    problems = []
    _unknown_keys(fields, FIELDS_KEYS, "fields", problems)
    private = fields.get("private", [])
    if not isinstance(private, list):
        problems.append("fields.private: must be a list")
        private = []
    for i, f in enumerate(private):
        _unknown_keys(f, PRIVATE_KEYS, "fields.private[%d]" % i, problems)
        if not isinstance(f, dict) or not f.get("path"):
            problems.append("fields.private[%d].path: required" % i)
        elif not isinstance(f.get("category"), str) or not f["category"] or f["category"] in ("private", "times"):
            problems.append("fields.private[%d].category: required string, for example identifier, name, "
                            "content or your own (amount, location...); 'private' and 'times' are reserved" % i)
    if not isinstance(fields.get("times", []), list):
        problems.append("fields.times: must be a list of field paths")
    if problems:
        raise SpecError(problems)
    return fields


def check_views(views):
    problems = []
    _unknown_keys(views, VIEWS_KEYS, "views", problems)
    items = views.get("views")
    if not isinstance(items, list) or not items:
        raise SpecError(problems + ["views.views: required non-empty list"])
    names = set()
    for i, v in enumerate(items):
        where = "views.views[%d] (%s)" % (i, v.get("name") if isinstance(v, dict) else "?")
        _unknown_keys(v, VIEW_KEYS, where, problems)
        if not isinstance(v, dict):
            continue
        if not v.get("name") or v["name"] in names:
            problems.append("%s.name: required and unique" % where)
        names.add(v.get("name"))
        for j, op in enumerate(v.get("ops", [])):
            w = "%s.ops[%d]" % (where, j)
            kind = op.get("op") if isinstance(op, dict) else None
            if kind not in BUILTIN_OPS:
                problems.append("%s.op: %r must be one of %s%s" % (w, kind, ", ".join(BUILTIN_OPS), hint(kind, BUILTIN_OPS)))
                continue
            _unknown_keys(op, OP_KEYS[kind], w, problems)
            if kind not in ("keep", "exec") and not op.get("fields"):
                problems.append("%s.fields: required (selectors such as \"private\", a category, \"times\" "
                                "or field paths)" % w)
            if kind == "alias" and op.get("scope", "run") != "run":
                problems.append("%s: alias supports scope 'run' only (use pseudonym for event/global)" % w)
            if kind == "pseudonym" and op.get("scope", "run") not in SCOPES:
                problems.append("%s.scope: must be one of %s" % (w, ", ".join(SCOPES)))
            if kind == "bucket" and not (isinstance(op.get("size"), (int, float)) and not isinstance(op.get("size"), bool)
                                         and op["size"] > 0):
                problems.append("%s.size: bucket needs a positive number" % w)
            if kind == "partial" and not (isinstance(op.get("keep_last"), int) and op["keep_last"] > 0):
                problems.append("%s.keep_last: partial needs a positive integer (characters kept at the end)" % w)
            if kind == "exec" and not op.get("command"):
                problems.append("%s.command: exec needs a command" % w)
    if problems:
        raise SpecError(problems)
    return views
