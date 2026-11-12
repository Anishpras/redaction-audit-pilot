"""Run an audit: render every view, review every run, score, write outputs."""
from __future__ import annotations

import csv
import datetime
import hashlib
import json
import os
import platform
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections import OrderedDict, defaultdict
from pathlib import Path

from . import __version__, cases as cases_mod, evaluate, spec, transforms

AUTH, UNAUTH, INSUFF = evaluate.AUTH, evaluate.UNAUTH, evaluate.INSUFF
STATUS_ORDER = {"verified": 0, "untested": 0, "unverifiable": 1, "unsafe": 2}
NEED_GUIDANCE = {
    "equality": "Keep both values, or replace them with pseudonyms that stay consistent across every event "
                "(this also holds for 'different' rules such as four-eyes checks) "
                "the condition compares (scope run or global). Uniform masks remove the relation. Per-event "
                "pseudonyms remove it too, and if undeclared they turn every authorised action into a false alarm.",
    "order": "Keep the exact values (times, amounts, counts), or within-run ranks that preserve order and ties. "
             "Coarsened (bucketed) values leave boundary cases undecidable, and if undeclared they produce "
             "confident wrong verdicts.",
    "explicit_state": "Record the state explicitly, including the 'clear' state (for example not_revoked), "
                      "together with the time it took effect. A missing field must never stand for the clear "
                      "state, because it cannot be told apart from redacted evidence.",
    "raw_value": "The value itself (or a non-identifying category that still answers the condition) must stay "
                 "visible. Masking and pseudonymising remove it.",
    "presence": "If a transform drops the field it must declare the drop; otherwise absence reads as a violation.",
}


def frac(n, of):
    return OrderedDict([("n", n), ("of", of)])


def show(fr):
    return "%d/%d" % (fr["n"], fr["of"])


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ------------------------------------------------------------------ reviewers
def _exec_reviewer(argv, policy, input_bytes, env_keep, timeout):
    env = {k: os.environ[k] for k in env_keep if k in os.environ}
    env.setdefault("PATH", os.environ.get("PATH", ""))
    if os.name == "nt":
        env.setdefault("SYSTEMROOT", os.environ.get("SYSTEMROOT", ""))
    payload = transforms.canonical_bytes({"policy": policy, "log": json.loads(input_bytes)})
    with tempfile.TemporaryDirectory(prefix="reviewer-") as workdir:
        proc = subprocess.run(argv, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd=workdir, env=env, timeout=timeout)
    try:
        out = json.loads(proc.stdout.decode("utf-8"))
        if out.get("verdict") not in (AUTH, UNAUTH, INSUFF):
            raise ValueError
        return out
    except ValueError:
        return {"verdict": INSUFF, "error": "unparseable reviewer output (exit %d)" % proc.returncode}


def make_reviewer(spec_str, policy, env_keep=(), timeout=120):
    if spec_str in ("builtin", "declared"):
        return lambda b: evaluate.evaluate(policy, json.loads(b), declared=True), "builtin (declared)"
    if spec_str == "undeclared":
        return lambda b: evaluate.evaluate(policy, json.loads(b), declared=False), "builtin (undeclared)"
    if spec_str.startswith("exec:"):
        argv = [os.path.abspath(a) if os.path.exists(a) else a for a in shlex.split(spec_str[5:])]
        return (lambda b: _exec_reviewer(argv, policy, b, env_keep, timeout)), "exec: " + " ".join(argv)
    raise spec.SpecError("--reviewer must be builtin, undeclared or exec:<command>")


# ------------------------------------------------------------------ metrics
def _families(pairs):
    out = []
    for p in pairs:
        if p["family"] not in out:
            out.append(p["family"])
    return out


def identical_pairs(inputs, pairs, families):
    by_family = OrderedDict((f, [0, 0]) for f in families)
    total = 0
    for p in pairs:
        by_family[p["family"]][1] += 1
        if inputs[p["auth"]] == inputs[p["unauth"]]:
            total += 1
            by_family[p["family"]][0] += 1
    return OrderedDict([("identical", frac(total, len(pairs))),
                        ("by_family", OrderedDict((f, frac(*v)) for f, v in by_family.items()))])


def ceiling(inputs, runs):
    groups = OrderedDict()
    for rid, run in runs.items():
        groups.setdefault(sha(inputs[rid]), []).append(run["label"])
    majority = sum(max(g.count(AUTH), g.count(UNAUTH)) for g in groups.values())
    return OrderedDict([("majority_sum", majority), ("runs", len(runs)),
                        ("ceiling", round(majority / len(runs), 4)), ("distinct_inputs", len(groups))])


def reviewer_counts(rows):
    n = len(rows)
    auth = [r for r in rows if r[0] == AUTH]
    unauth = [r for r in rows if r[0] == UNAUTH]
    correct = sum(e == v for e, v in rows)
    abstain = sum(v == INSUFF for _, v in rows)
    return OrderedDict([
        ("correct", frac(correct, n)),
        ("missed_violations", frac(sum(v == AUTH for _, v in unauth), len(unauth))),
        ("false_alarms", frac(sum(v == UNAUTH for _, v in auth), len(auth))),
        ("abstentions", frac(abstain, n)),
        ("definitive_coverage", frac(n - abstain, n)),
        ("authorised_confirmed", frac(sum(v == AUTH for _, v in auth), len(auth))),
        ("violations_detected", frac(sum(v == UNAUTH for _, v in unauth), len(unauth))),
    ])


def reviewer_metrics(verdicts, runs, pairs, families):
    out = reviewer_counts([(runs[r]["label"], verdicts[r]) for r in runs])
    by_family = OrderedDict()
    for f in families:
        members = []
        for p in pairs:
            if p["family"] == f:
                for rid in (p["auth"], p["unauth"]):
                    if rid not in members:
                        members.append(rid)
        by_family[f] = reviewer_counts([(runs[r]["label"], verdicts[r]) for r in members])
    out["by_family"] = by_family
    return out


def exposure(inputs, runs, fields):
    summed_vis = summed_all = 0
    distinct, distinct_vis = OrderedDict(), set()
    for rid, run in runs.items():
        planted = transforms.planted_values(run["log"], fields)
        vis = set(transforms.visible_values(inputs[rid], planted))
        summed_all += len(planted)
        summed_vis += len(vis)
        for v, cat in planted.items():
            distinct.setdefault(v, cat)
            if v in vis:
                distinct_vis.add(v)
    return OrderedDict([("distinct_values", frac(len(distinct_vis), len(distinct))),
                        ("summed_over_inputs", frac(summed_vis, summed_all))])


def exposure_by_field(inputs, runs, fields):
    rows = []
    for f in fields.get("private", []):
        seen, vis = set(), set()
        for rid, run in runs.items():
            values = {str(transforms.paths.get(ev, f["path"])) for ev in run["log"]["events"]
                      if transforms.paths.get(ev, f["path"], None) not in (None, transforms.paths.MISSING)}
            for value in values:
                seen.add(value)
                if transforms.visible_values(inputs[rid], {value: f["category"]}):
                    vis.add(value)
        rows.append((f["path"], f["category"], len(vis), len(seen)))
    return rows


def condition_matrix(policy, results, runs, pairs, inputs):
    """Per condition: what happens to it under this view (uses per-condition checks when given)."""
    out = OrderedDict()
    auth_runs = [r for r in runs if runs[r]["label"] == AUTH]
    for cond in policy["conditions"]:
        cid = cond["id"]
        target_pairs = [p for p in pairs if p["target"] == cid]
        row = OrderedDict([("need", cond["need"]), ("confirmed", 0), ("unconfirmed", 0), ("false_alarms", 0),
                           ("detected", 0), ("undetected", 0), ("missed", 0),
                           ("pairs", len(target_pairs)), ("pairs_collapsed", 0)])
        cases_of = {"unconfirmed": [], "false_alarms": [], "undetected": [], "missed": []}
        for r in auth_runs:
            res = results[r]
            c = res.get("checks", {}).get(cid) if res.get("checks") else None
            if c is None:
                c = {AUTH: "pass", UNAUTH: "fail", INSUFF: "unknown"}[res["verdict"]]
            key = {"pass": "confirmed", "unknown": "unconfirmed", "fail": "false_alarms"}[c]
            row[key] += 1
            if key in cases_of:
                cases_of[key].append(r)
        for p in target_pairs:
            res = results[p["unauth"]]
            c = res.get("checks", {}).get(cid) if res.get("checks") else None
            if c is None:
                c = {UNAUTH: "fail", INSUFF: "unknown", AUTH: "pass"}[res["verdict"]]
            key = {"fail": "detected", "unknown": "undetected", "pass": "missed"}[c]
            row[key] += 1
            if key in cases_of:
                cases_of[key].append(p["pair_id"])
            if inputs[p["auth"]] == inputs[p["unauth"]]:
                row["pairs_collapsed"] += 1
        if row["false_alarms"] or row["missed"]:
            row["status"] = "unsafe"
        elif row["unconfirmed"] or row["undetected"]:
            row["status"] = "unverifiable"
        elif not target_pairs:
            row["status"] = "untested"  # no case violates it, so a wrong "pass" could not be caught
        else:
            row["status"] = "verified"
        for key, ids in cases_of.items():
            row["%s_cases" % key] = ";".join(ids)
        out[cid] = row
    return out


# ------------------------------------------------------------------ outputs
def _write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def _status_table(policy, view_names, matrices):
    lines = ["| Condition | Need | " + " | ".join(view_names) + " |", "|---|---|" + "---|" * len(view_names)]
    for cond in policy["conditions"]:
        cells = []
        for v in view_names:
            st = matrices[v][cond["id"]]["status"]
            cells.append({"verified": "verified", "untested": "untested", "unverifiable": "unverifiable",
                          "unsafe": "**UNSAFE**"}[st])
        lines.append("| %s | %s | %s |" % (cond["id"], cond["need"], " | ".join(cells)))
    return lines


def _matrix_md(policy, view_names, matrices, undeclared=None):
    lines = ["# Condition x view matrix: %s" % policy.get("name", "policy"), "",
             "Status per condition and view: **verified** (every authorised case confirmed and every "
             "targeted violation detected), **unverifiable** (some cases left undecided) or **UNSAFE** "
             "(the reviewer gave at least one wrong verdict). **untested** means no case violates the condition, "
             "so a reviewer that wrongly passes it would not be caught.", ""]
    lines += _status_table(policy, view_names, matrices)
    if undeclared:
        lines += ["", "## Same views read without the redaction header (undeclared reading)", "",
                  "What a reviewer who does not know how the log was redacted would conclude. Cells that are "
                  "**UNSAFE** here but not above mean the scheme is safe only while its declaration travels with "
                  "the log.", ""]
        lines += _status_table(policy, view_names, undeclared)
    lines += ["", "## Counts (declared reading)", "",
              "Authorised side: confirmed / unconfirmed / false alarms. Violation side (cases targeting this "
              "condition): detected / undetected / missed. Collapsed: targeted pairs whose two inputs are "
              "byte-identical.", "",
              "| View | Condition | Status | Authorised (conf/unconf/false) | Violations (det/undet/missed) | Collapsed |",
              "|---|---|---|---|---|---|"]
    for v in view_names:
        for cid, r in matrices[v].items():
            lines.append("| %s | %s | %s | %d/%d/%d | %d/%d/%d | %d/%d |" % (
                v, cid, r["status"], r["confirmed"], r["unconfirmed"], r["false_alarms"],
                r["detected"], r["undetected"], r["missed"], r["pairs_collapsed"], r["pairs"]))
    problems = [(v, cid, r) for v in view_names for cid, r in matrices[v].items()
                if r["false_alarms"] or r["missed"] or r["unconfirmed"] or r["undetected"]]
    if problems:
        lines += ["", "## Cases behind each problem (declared reading)", "",
                  "Authorised cases are named by case id, violations by pair id (base~condition). "
                  "Exact inputs are in inputs/<view>/<case id>.json.", ""]
        for v, cid, r in problems:
            parts = []
            for key, label in (("false_alarms", "false alarm"), ("missed", "missed"),
                               ("unconfirmed", "unconfirmed"), ("undetected", "undetected")):
                ids = [x for x in r["%s_cases" % key].split(";") if x]
                if ids:
                    shown = ", ".join(ids[:6]) + (" and %d more" % (len(ids) - 6) if len(ids) > 6 else "")
                    parts.append("%s: %s" % (label, shown))
            lines.append("- **%s / %s:** %s" % (v, cid, "; ".join(parts)))
    return "\n".join(lines) + "\n"


def _describe(cond):
    if cond["need"] == "equality":
        return "`%s` equals `%s`" % (cond["left"], cond["right"])
    if cond["need"] == "order":
        return "`%s %s %s`" % (cond["left"], cond["op"], cond["right"])
    if cond["need"] == "explicit_state":
        s = "`%s` in %s (violated by %s" % (cond["field"], cond["pass"], cond["fail"])
        if "fail_only_if" in cond:
            f = cond["fail_only_if"]
            s += " when `%s %s %s`" % (f["left"], f["op"], f["right"])
        return s + ")"
    if cond["need"] == "raw_value":
        return "`%s` in %s" % (cond["field"], cond["allowed"])
    return "`%s` is present" % cond["field"]


def evidence_requirements_md(policy, view_names=None, matrices=None):
    lines = ["# Evidence requirements: %s" % policy.get("name", "policy"), ""]
    if policy.get("description"):
        lines += [policy["description"], ""]
    lines += ["A redacted log can be audited against this policy only if it keeps the evidence below. "
              "Each condition is listed with its *need type*; the guidance says which redaction forms "
              "preserve it. Generated by redaction_audit %s." % __version__, ""]
    for cond in policy["conditions"]:
        lines += ["## %s (%s)" % (cond["id"], cond["need"]), "",
                  "- **Rule:** %s" % _describe(cond),
                  "- **What the log must keep:** %s" % NEED_GUIDANCE[cond["need"]]]
        if matrices:
            ok = [v for v in view_names if matrices[v][cond["id"]]["status"] == "verified"]
            bad = ["%s (%s)" % (v, matrices[v][cond["id"]]["status"]) for v in view_names
                   if matrices[v][cond["id"]]["status"] != "verified"]
            lines.append("- **Tested views that keep it:** %s" % (", ".join(ok) or "none"))
            lines.append("- **Tested views that lose it:** %s" % (", ".join(bad) or "none"))
        lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------ main entry
def run(policy_path, fields_path, cases_path, views_path, out_dir, reviewer="builtin",
        seed=20261113, env_keep=(), fail_on=(), gate=None, quiet=False):
    policy = spec.check_policy(spec.load_json(policy_path))
    fields = spec.check_fields(spec.load_json(fields_path))
    views = spec.check_views(spec.load_json(views_path))
    runs, pairs, mode = cases_mod.load(policy, spec.load_jsonl(cases_path))
    transforms.check_selectors(views, fields, [r["log"] for r in runs.values()])
    review, reviewer_desc = make_reviewer(reviewer, policy, env_keep)
    both = reviewer in ("builtin", "declared")
    base_dir = str(Path(views_path).resolve().parent)
    families = _families(pairs)
    run_ids = list(runs)

    view_names = [v["name"] for v in views["views"]]
    inputs, results = {}, {}
    jobs = [(v, rid) for v in views["views"] for rid in run_ids]
    order = list(range(len(jobs)))
    random.Random(seed).shuffle(order)  # call order carries no label information
    rendered = {}
    for i in order:
        v, rid = jobs[i]
        b = transforms.render(v, rid, runs[rid]["log"], fields, base_dir)
        rendered[(v["name"], rid)] = b
        results[(v["name"], rid)] = review(b)
    for v in view_names:
        inputs[v] = {rid: rendered[(v, rid)] for rid in run_ids}

    summary, fam_rows, matrices, flat = OrderedDict(), [], OrderedDict(), []
    undeclared, exposure_rows = OrderedDict(), []
    for v in views["views"]:
        name = v["name"]
        verdicts = {rid: results[(name, rid)]["verdict"] for rid in run_ids}
        m1 = identical_pairs(inputs[name], pairs, families)
        m2 = ceiling(inputs[name], runs)
        m3 = reviewer_metrics(verdicts, runs, pairs, families)
        m4 = exposure(inputs[name], runs, fields)
        matrices[name] = condition_matrix(policy, {rid: results[(name, rid)] for rid in run_ids},
                                          runs, pairs, inputs[name])
        if both:
            undeclared[name] = condition_matrix(
                policy, {rid: evaluate.evaluate(policy, json.loads(inputs[name][rid]), declared=False)
                         for rid in run_ids}, runs, pairs, inputs[name])
        for path, cat, vis, total in exposure_by_field(inputs[name], runs, fields):
            exposure_rows.append(OrderedDict([("view", name), ("field", path), ("category", cat),
                                              ("visible", vis), ("distinct_values", total)]))
        worst = max((r["status"] for r in matrices[name].values()), key=STATUS_ORDER.get)
        worst = "verified" if worst == "untested" else worst
        summary[name] = OrderedDict([("role", v.get("role", "")), ("status", worst), ("identical_pairs", m1),
                                     ("ceiling", m2), ("reviewer", m3), ("exposure", m4)])
        row = OrderedDict([("view", name), ("role", v.get("role", "")), ("identical_pairs", show(m1["identical"]))])
        for f in families:
            row["identical_%s" % f] = show(m1["by_family"][f])
        row.update([
            ("ceiling", "%d/%d" % (m2["majority_sum"], m2["runs"])), ("ceiling_value", m2["ceiling"]),
            ("distinct_inputs", m2["distinct_inputs"]),
            ("correct", show(m3["correct"])), ("missed_violations", show(m3["missed_violations"])),
            ("false_alarms", show(m3["false_alarms"])), ("abstentions", show(m3["abstentions"])),
            ("definitive_coverage", show(m3["definitive_coverage"])),
            ("authorised_confirmed", show(m3["authorised_confirmed"])),
            ("violations_detected", show(m3["violations_detected"])),
            ("exposure_distinct", show(m4["distinct_values"])),
            ("exposure_summed", show(m4["summed_over_inputs"])),
        ])
        flat.append(row)
        for f, m in m3["by_family"].items():
            fam_rows.append(OrderedDict([
                ("view", name), ("family", f), ("identical_pairs", show(m1["by_family"][f])),
                ("correct", show(m["correct"])), ("missed_violations", show(m["missed_violations"])),
                ("false_alarms", show(m["false_alarms"])), ("abstentions", show(m["abstentions"])),
                ("authorised_confirmed", show(m["authorised_confirmed"])),
                ("violations_detected", show(m["violations_detected"])),
            ]))

    out = Path(out_dir)
    if out.exists():
        shutil.rmtree(out)
    (out / "inputs").mkdir(parents=True)
    for (name, rid), b in rendered.items():
        p = out / "inputs" / name / ("%s.json" % rid)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b)
    _write_csv(out / "summary.csv", flat)
    _write_csv(out / "family_breakdown.csv", fam_rows)
    mrows = []
    for name in view_names:
        for cid, r in matrices[name].items():
            mrows.append(OrderedDict([("view", name), ("condition", cid)] + list(r.items())))
    _write_csv(out / "matrix.csv", mrows)
    (out / "matrix.md").write_text(_matrix_md(policy, view_names, matrices, undeclared or None), encoding="utf-8")
    _write_csv(out / "exposure.csv", exposure_rows)
    if both:
        _write_csv(out / "readings.csv", [OrderedDict([
            ("view", name), ("condition", cid), ("declared", matrices[name][cid]["status"]),
            ("undeclared", undeclared[name][cid]["status"])]) for name in view_names for cid in matrices[name]])
    (out / "evidence_requirements.md").write_text(
        evidence_requirements_md(policy, view_names, matrices), encoding="utf-8")
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    pair_of = {}
    for p in pairs:
        pair_of.setdefault(p["auth"], []).append(p["pair_id"])
        pair_of.setdefault(p["unauth"], []).append(p["pair_id"])
    with open(out / "per_case.jsonl", "w", encoding="utf-8") as fh:
        for name in view_names:
            for rid in run_ids:
                fh.write(json.dumps(OrderedDict([
                    ("view", name), ("case_id", rid), ("label", runs[rid]["label"]),
                    ("pairs", pair_of.get(rid, [])), ("result", results[(name, rid)]),
                    ("input_sha256", sha(inputs[name][rid]))]), sort_keys=False) + "\n")
    meta = OrderedDict([
        ("tool", "redaction_audit %s" % __version__),
        ("run_at_utc", datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")),
        ("python", sys.version.split()[0]), ("platform", platform.platform()),
        ("mode", mode), ("runs", len(runs)), ("pairs", len(pairs)), ("reviewer", reviewer_desc),
        ("call_order_seed", seed),
        ("inputs_sha256", OrderedDict((k, hashlib.sha256(Path(p).read_bytes()).hexdigest()) for k, p in
                                      (("policy", policy_path), ("fields", fields_path),
                                       ("cases", cases_path), ("views", views_path)))),
    ])
    (out / "run.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    failures = []
    if fail_on:
        gate_views = gate or view_names
        for name in gate_views:
            if name not in matrices:
                raise spec.SpecError("--gate view %r is not defined%s" % (name, spec.hint(name, view_names)))
            for cid, r in matrices[name].items():
                if r["status"] in fail_on:
                    failures.append("%s / %s: %s" % (name, cid, r["status"]))
            if "unsafe-undeclared" in fail_on:
                if not both:
                    raise spec.SpecError("--fail-on unsafe-undeclared needs the builtin reviewer")
                for cid, r in undeclared[name].items():
                    if r["status"] == "unsafe":
                        failures.append("%s / %s: unsafe when read without the redaction header" % (name, cid))
            if "exposed" in fail_on:
                for row in exposure_rows:
                    if row["view"] == name and row["visible"]:
                        failures.append("%s: %d of %d values of private field %s are visible"
                                        % (name, row["visible"], row["distinct_values"], row["field"]))
    if not quiet:
        print("redaction_audit %s | %s | %d runs, %d pairs (%s) | reviewer: %s"
              % (__version__, policy.get("name", "policy"), len(runs), len(pairs), mode, reviewer_desc))
        print()
        width = max(len(n) for n in view_names) + 2
        def worst_of(m):
            w = max((r["status"] for r in m.values()), key=STATUS_ORDER.get)
            return "verified" if w == "untested" else w
        print("%-*s %-13s %-13s %-9s %-8s %-7s %-8s %-9s %s" % (width, "view", "status", "undeclared", "ident.",
                                                              "correct", "missed", "f.alarm", "abstain", "exposed"))
        for row, name in zip(flat, view_names):
            print("%-*s %-13s %-13s %-9s %-8s %-7s %-8s %-9s %s" % (
                width, name, summary[name]["status"], worst_of(undeclared[name]) if both else "-",
                row["identical_pairs"], row["correct"], row["missed_violations"], row["false_alarms"],
                row["abstentions"], row["exposure_distinct"]))
        print("\nWrote %s (matrix.md, evidence_requirements.md, summary.csv, exposure.csv, per_case.jsonl, inputs/)" % out)
        if failures:
            print("\nGATE FAILED (%s):" % ", ".join(fail_on))
            for f in failures:
                print("  " + f)
    return 1 if failures else 0
