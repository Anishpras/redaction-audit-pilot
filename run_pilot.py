#!/usr/bin/env python3
"""Reproduce the redaction audit pilot.

    python3 run_pilot.py                    # validate, run the reviewer twice, score, write results/
    python3 run_pilot.py --show-pair P01    # print every view's exact input and verdict for one pair
    python3 run_pilot.py --rebuild-fixtures # regenerate data/ from pilot/fixtures.py (intentional changes only)
    python3 run_pilot.py --freeze --freeze-label v1.1 --freeze-note "..."   # record hashes (pre-run)

Standard library only. No network. Randomness: the recorded sanity seed and call-order seeds.
The default command never modifies data/; it only writes results/.
"""
from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import io
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from pilot import exposure, fixtures, scoring, validate, views  # noqa: E402
from pilot import reviewer as reviewer_module  # noqa: E402  (supplementary in-process use only)

REVIEWER = ROOT / "pilot" / "reviewer.py"
DATA = ROOT / "data"
FREEZE = ROOT / "FREEZE.json"
FROZEN_FILES = [
    "PROTOCOL.md", "data/fixtures.json", "data/manifest.json", "run_pilot.py",
    "pilot/__init__.py", "pilot/fixtures.py", "pilot/policy.py", "pilot/views.py", "pilot/reviewer.py",
    "pilot/exposure.py", "pilot/scoring.py", "pilot/validate.py",
    "tests/__init__.py", "tests/test_rules.py", "tests/test_scoring.py",
]
ORDER_SEEDS = (20261113, 20261114)  # reviewer call-order shuffles for pass 1 and pass 2
CONDITIONS = ["document_matches", "recipient_matches", "purpose_matches",
              "at_or_after_grant", "before_expiry", "not_revoked"]


# ---------------------------------------------------------------- helpers
def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def dump_json(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=False) + "\n"


def show(fr) -> str:
    return "%d/%d" % (fr["n"], fr["of"])


def run_reviewer(input_bytes: bytes, naive: bool = False) -> dict:
    """One isolated reviewer call: a fresh empty temporary directory holding only a copy of the
    reviewer, `python3 -I`, an empty environment, input on stdin only. argv[0] is the bare
    filename, so the call reveals no project path. This is process-level isolation, not an OS
    sandbox: a malicious reviewer could still read absolute paths it guessed."""
    with tempfile.TemporaryDirectory(prefix="reviewer-") as workdir:
        shutil.copyfile(REVIEWER, os.path.join(workdir, "reviewer.py"))
        cmd = [sys.executable, "-I", "reviewer.py"] + (["--naive-mask-equality"] if naive else [])
        proc = subprocess.run(cmd, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd=workdir, env={}, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError("reviewer failed: " + proc.stderr.decode(errors="replace"))
    return json.loads(proc.stdout.decode("utf-8"))


def run_pass(records, sanity_records, seed):
    """One complete pass over every (view, case) job, executed in a seeded random order so the
    call sequence carries no label information. Results are returned in a fixed job order."""
    jobs = [("core", v, r) for v in views.VIEWS for r in records]
    jobs += [("naive", "B_uniform_mask", r) for r in records]
    jobs += [("sanity", v, r) for r in sanity_records for v in views.VIEWS]
    order = list(range(len(jobs)))
    random.Random(seed).shuffle(order)
    outputs = [None] * len(jobs)
    for i in order:
        kind, view, rec = jobs[i]
        b = views.render(view, rec)
        outputs[i] = {"input": b, "review": run_reviewer(b, naive=(kind == "naive"))}
    out = {"core": OrderedDict(), "naive": OrderedDict(), "sanity": OrderedDict()}
    for (kind, view, rec), result in zip(jobs, outputs):
        key = rec["case_id"] if kind == "naive" else (view, rec["case_id"])
        out[kind][key] = result
    return out


def run_unit_tests():
    suite = unittest.TestLoader().discover(str(ROOT / "tests"), top_level_dir=str(ROOT))
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    return [validate._result("unit_tests", result.wasSuccessful(), "ran=%d failures=%d errors=%d"
                             % (result.testsRun, len(result.failures), len(result.errors)))]


def load_freeze():
    if not FREEZE.exists():
        return {"history": []}
    data = json.loads(FREEZE.read_text(), object_pairs_hook=OrderedDict)
    if "history" not in data:  # v1.0 format: a single entry
        data = OrderedDict([("history", [OrderedDict([("label", "v1.0")] + list(data.items()))])])
    return data


def freeze_status():
    history = load_freeze()["history"]
    if not history:
        return OrderedDict([("frozen", False), ("matches", False), ("label", None), ("mismatched", [])])
    latest = history[-1]
    mismatched = [f for f, h in latest["sha256"].items()
                  if not (ROOT / f).exists() or sha256_file(ROOT / f) != h]
    unfrozen = [f for f in FROZEN_FILES if f not in latest["sha256"]]
    return OrderedDict([("frozen", True), ("label", latest["label"]),
                        ("frozen_at_utc", latest["frozen_at_utc"]),
                        ("matches", not mismatched and not unfrozen),
                        ("mismatched", mismatched), ("not_covered", unfrozen)])


def metric_block(inputs, verdicts, cases, by_id, case_ids, with_exposure=True):
    block = OrderedDict([
        ("metric1_identical_pairs", scoring.identical_pairs(inputs, cases)),
        ("metric2_ceiling", scoring.ceiling(inputs, cases)),
        ("metric3_reviewer", scoring.reviewer_metrics(verdicts, cases)),
    ])
    if with_exposure:
        block["metric4_exposure"] = scoring.exposure_metrics(inputs, by_id, case_ids)
    return block


# ---------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="results", help="output directory (default: results)")
    ap.add_argument("--show-pair", metavar="PAIR_ID", help="print views and verdicts for one pair, then exit")
    ap.add_argument("--rebuild-fixtures", action="store_true", help="write data/ from pilot/fixtures.py")
    ap.add_argument("--freeze", action="store_true", help="append current hashes to FREEZE.json")
    ap.add_argument("--freeze-label", default=None)
    ap.add_argument("--freeze-note", default="")
    args = ap.parse_args(argv)

    # ---- fixtures: compare the stored files with the specification before anything else
    mem_records, mem_sanity, mem_manifest = fixtures.build()
    want_fixtures = fixtures.dumps_fixtures(mem_records, mem_sanity)
    want_manifest = fixtures.dumps_manifest(mem_manifest)
    if args.rebuild_fixtures:
        write_text(DATA / "fixtures.json", want_fixtures)
        write_text(DATA / "manifest.json", want_manifest)
        print("Rebuilt data/fixtures.json and data/manifest.json (fixture version %s)." % fixtures.FIXTURE_VERSION)
        return 0
    if not (DATA / "fixtures.json").exists() or not (DATA / "manifest.json").exists():
        print("data/ is missing; run with --rebuild-fixtures first.")
        return 2

    if args.freeze:
        payload = load_freeze()
        payload["history"].append(OrderedDict([
            ("label", args.freeze_label or "v%s" % fixtures.FIXTURE_VERSION),
            ("frozen_at_utc", datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")),
            ("fixture_version", fixtures.FIXTURE_VERSION),
            ("note", args.freeze_note),
            ("sha256", OrderedDict((f, sha256_file(ROOT / f)) for f in FROZEN_FILES)),
        ]))
        write_text(FREEZE, dump_json(payload))
        print("Appended freeze entry %s to FREEZE.json" % payload["history"][-1]["label"])
        return 0

    stored = json.loads((DATA / "fixtures.json").read_text(), object_pairs_hook=OrderedDict)
    records, sanity_records = stored["records"], stored["sanity_records"]
    manifest = json.loads((DATA / "manifest.json").read_text(), object_pairs_hook=OrderedDict)
    cases = manifest["cases"]
    by_id = {r["case_id"]: r for r in records}
    case_ids = [c["case_id"] for c in cases]

    if args.show_pair:
        for c in [c for c in cases if c["pair_id"] == args.show_pair]:
            for view in views.VIEWS:
                b = views.render(view, by_id[c["case_id"]])
                print("%s %-12s %-16s -> %s" % (c["pair_id"], c["role"], view, run_reviewer(b)["verdict"]))
                print("   ", b.decode())
        return 0

    out = ROOT / args.out
    checks = []
    data_ok = ((DATA / "fixtures.json").read_text() == want_fixtures
               and (DATA / "manifest.json").read_text() == want_manifest)
    checks.append(validate._result("data_files_match_fixture_spec", data_ok,
                                   "" if data_ok else "stored data/ differs from pilot/fixtures.py"))
    frz = freeze_status()
    checks.append(validate._result("freeze_hashes_match_current_files", frz["matches"],
                                   "label=%s mismatched=%s not_covered=%s" % (
                                       frz.get("label"), frz.get("mismatched"), frz.get("not_covered"))))

    # ---- pre-run validation
    checks += validate.check_labels(records, manifest)
    checks += validate.check_sanity_labels(sanity_records, manifest)
    checks += validate.check_pairs(records, manifest)
    checks += validate.check_boundary_coverage(records, manifest)
    checks += validate.check_planted_values(records)
    checks += validate.check_reviewer_static(REVIEWER)
    checks += validate.check_canonical_determinism(records, fixtures.SANITY_SEED)
    checks += validate.check_exposure_scanner(records)
    checks += run_unit_tests()
    blocking = [c for c in checks if not c["ok"] and c["check"] != "freeze_hashes_match_current_files"]
    if blocking:
        print("PRE-RUN VALIDATION FAILED; not running the reviewer:")
        for c in blocking:
            print("  FAIL", c["check"], c["detail"])
        return 2

    # ---- two independent passes, each in its own shuffled call order
    pass1 = run_pass(records, sanity_records, ORDER_SEEDS[0])
    pass2 = run_pass(records, sanity_records, ORDER_SEEDS[1])
    same = all(pass1[k] == pass2[k] for k in pass1)
    checks.append(validate._result("second_pass_reproduces_inputs_and_verdicts", same,
                                   "pass orders seeded %s and %s" % ORDER_SEEDS))
    res = pass1
    verdicts = {v: {cid: res["core"][(v, cid)]["review"]["verdict"] for cid in case_ids} for v in views.VIEWS}
    inputs = {v: {cid: res["core"][(v, cid)]["input"] for cid in case_ids} for v in views.VIEWS}

    # ---- gate: the full view must reproduce every label before any other view is scored
    gate = validate.check_full_view_matches_labels(verdicts["A_full"], manifest)
    checks += gate
    if not gate[0]["ok"]:
        write_text(out / "validation.json", dump_json(checks))
        print("GATE FAILED: full-view reviewer disagrees with labels; other views not scored.")
        print("  ", gate[0]["detail"])
        return 3

    rendered_all = {(v, cid): d["input"] for (v, cid), d in res["core"].items()}
    rendered_all.update({(v, sid): d["input"] for (v, sid), d in res["sanity"].items()})
    checks += validate.check_inputs_carry_no_metadata(rendered_all, records + sanity_records, manifest)

    sanity_results = OrderedDict()
    for sc in manifest["sanity_cases"]:
        sanity_results[sc["case_id"]] = OrderedDict(
            (v, {"verdict": res["sanity"][(v, sc["case_id"])]["review"]["verdict"],
                 "base_verdict": verdicts[v][sc["base_case_id"]],
                 "identical_to_base": res["sanity"][(v, sc["case_id"])]["input"] == inputs[v][sc["base_case_id"]]})
            for v in views.VIEWS)
    checks += validate.check_sanity(sanity_results, manifest)

    # ---- scoring
    summary_views = OrderedDict()
    for v in views.VIEWS:
        block = OrderedDict([("role", "core" if v in views.CORE_VIEWS else "ablation")])
        block.update(metric_block(inputs[v], verdicts[v], cases, by_id, case_ids))
        summary_views[v] = block
    n_auth = sum(c["expected_verdict"] == "authorised" for c in cases)
    checks += validate.check_metric_invariants(summary_views, len(cases), n_auth)
    naive_verdicts = {cid: res["naive"][cid]["review"]["verdict"] for cid in case_ids}

    # ---- supplementary: shared-timeline variant (robustness of metrics 1-3 to cross-pair collisions)
    st_records, st_cases = fixtures.build_shared_timeline()
    checks += validate.check_shared_timeline_labels(st_records, st_cases)
    st_by_id = {r["case_id"]: r for r in st_records}
    st_ids = [c["case_id"] for c in st_cases]
    shared = OrderedDict()
    for v in views.VIEWS:
        st_inputs = {cid: views.render(v, st_by_id[cid]) for cid in st_ids}
        st_verdicts = {cid: reviewer_module.review(json.loads(st_inputs[cid]))["verdict"] for cid in st_ids}
        blk = metric_block(st_inputs, st_verdicts, st_cases, st_by_id, st_ids, with_exposure=False)
        shared[v] = OrderedDict([
            ("identical_pairs", show(blk["metric1_identical_pairs"]["identical"])),
            ("distinct_inputs", blk["metric2_ceiling"]["distinct_inputs"]),
            ("ceiling", "%d/%d" % (blk["metric2_ceiling"]["majority_sum"], blk["metric2_ceiling"]["runs"])),
            ("reviewer_correct", show(blk["metric3_reviewer"]["correct"])),
            ("reviewer_abstentions", show(blk["metric3_reviewer"]["abstentions"])),
            ("mixed_label_groups", [g["case_ids"] for g in blk["metric2_ceiling"]["mixed_label_groups"]]),
        ])

    supplementary = OrderedDict([
        ("B_naive_mask_equality", OrderedDict([
            ("note", "Diagnostic only: same view-B inputs, reviewer compares mask strings as if they were "
                     "real identifiers. Not part of the pre-specified metrics."),
            ("metric3_reviewer", scoring.reviewer_metrics(naive_verdicts, cases)),
        ])),
        ("shared_timeline_variant", OrderedDict([
            ("note", "Added in v1.1, not pre-registered. Every pair moved onto P01's purpose and timeline "
                     "(case review; grant 10, share 20, expiry 30, not revoked), keeping only its varied fact. "
                     "Reviewer applied in-process (same function as the isolated script)."),
            ("views", shared),
        ])),
    ])
    summary = OrderedDict([
        ("title", "What Evidence Do AI Agent Audit Logs Need After Redaction? (pilot)"),
        ("fixture_version", manifest["fixture_version"]),
        ("runs", len(cases)), ("pairs", len(cases) // 2),
        ("views", summary_views),
        ("supplementary", supplementary),
        ("validation_all_ok", all(c["ok"] for c in checks)),
        ("frozen_run", frz["matches"]),
    ])

    # ---- outputs (everything except run_info.json is byte-reproducible)
    if out.exists():
        shutil.rmtree(out)
    (out / "inputs").mkdir(parents=True)
    for (v, cid), d in list(res["core"].items()) + list(res["sanity"].items()):
        p = out / "inputs" / v / ("%s.json" % cid)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(d["input"])

    case_meta = {c["case_id"]: c for c in cases}
    partner = {c["case_id"]: next(o["case_id"] for o in cases if o["pair_id"] == c["pair_id"] and o is not c)
               for c in cases}
    rows = []
    for v in views.VIEWS:
        for cid in case_ids:
            c, rv = case_meta[cid], res["core"][(v, cid)]["review"]
            planted = exposure.planted_values(by_id[cid])
            visible = exposure.visible_values(inputs[v][cid], planted)
            row = OrderedDict([
                ("view", v), ("case_id", cid), ("pair_id", c["pair_id"]), ("family", c["family"]),
                ("expected_verdict", c["expected_verdict"]), ("reviewer_verdict", rv["verdict"]),
                ("outcome", scoring.outcome_type(c["expected_verdict"], rv["verdict"])),
            ])
            for cond in CONDITIONS:
                row[cond] = rv["checks"].get(cond, "")
            row.update([
                ("identical_to_pair_partner", inputs[v][cid] == inputs[v][partner[cid]]),
                ("input_sha256", scoring.sha(inputs[v][cid])), ("input_bytes", len(inputs[v][cid])),
                ("planted_values", len(planted)), ("planted_visible", len(visible)),
                ("naive_mask_verdict", naive_verdicts[cid] if v == "B_uniform_mask" else ""),
            ])
            rows.append(row)
    with open(out / "per_case.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    flat = []
    for v, s in summary_views.items():
        m1, m2, m3, m4 = (s["metric1_identical_pairs"], s["metric2_ceiling"],
                          s["metric3_reviewer"], s["metric4_exposure"])
        flat.append(OrderedDict([
            ("view", v), ("role", s["role"]),
            ("identical_pairs", show(m1["identical"])),
            ("identical_recipient", show(m1["by_family"]["recipient"])),
            ("identical_document", show(m1["by_family"]["document"])),
            ("identical_expiry", show(m1["by_family"]["expiry"])),
            ("identical_revocation", show(m1["by_family"]["revocation"])),
            ("ceiling", "%d/%d" % (m2["majority_sum"], m2["runs"])), ("ceiling_value", m2["ceiling"]),
            ("distinct_inputs", m2["distinct_inputs"]),
            ("correct", show(m3["correct"])), ("missed_violations", show(m3["missed_violations"])),
            ("false_alarms", show(m3["false_alarms"])), ("abstentions", show(m3["abstentions"])),
            ("definitive_coverage", show(m3["definitive_coverage"])),
            ("authorised_confirmed", show(m3["authorised_confirmed"])),
            ("violations_detected", show(m3["violations_detected"])),
            ("exposure_distinct", show(m4["distinct_values"])),
            ("exposure_summed", show(m4["summed_over_inputs"])),
        ]))
    with open(out / "summary.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(flat[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(flat)

    fam_rows = []
    for v, s in summary_views.items():
        for fam, m in s["metric3_reviewer"]["by_family"].items():
            fam_rows.append(OrderedDict([
                ("view", v), ("family", fam),
                ("identical_pairs", show(s["metric1_identical_pairs"]["by_family"][fam])),
                ("correct", show(m["correct"])), ("missed_violations", show(m["missed_violations"])),
                ("false_alarms", show(m["false_alarms"])), ("abstentions", show(m["abstentions"])),
                ("authorised_confirmed", show(m["authorised_confirmed"])),
                ("violations_detected", show(m["violations_detected"])),
            ]))
    with open(out / "family_breakdown.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(fam_rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(fam_rows)

    with open(out / "sanity.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["sanity_case", "base_case", "base_pair_role", "change_type", "view", "verdict",
                     "base_verdict", "identical_to_base", "expected_identical"])
        for sc in manifest["sanity_cases"]:
            for v, d in sanity_results[sc["case_id"]].items():
                w.writerow([sc["case_id"], sc["base_case_id"], sc["base_pair_role"], sc["change_type"], v,
                            d["verdict"], d["base_verdict"], d["identical_to_base"],
                            v in sc["expected_identical_views"]])

    groups = OrderedDict((v, s["metric2_ceiling"]["mixed_label_groups"]) for v, s in summary_views.items())
    write_text(out / "mixed_label_groups.json", dump_json(groups))
    write_text(out / "summary.json", dump_json(summary))
    write_text(out / "validation.json", dump_json(checks))
    with open(out / "reviewer_outputs.jsonl", "w", encoding="utf-8") as fh:
        for (v, cid), d in res["core"].items():
            fh.write(json.dumps(OrderedDict([("view", v), ("case_id", cid), ("output", d["review"])])) + "\n")
        for cid, d in res["naive"].items():
            fh.write(json.dumps(OrderedDict([("view", "B_naive_mask_equality"), ("case_id", cid),
                                             ("output", d["review"])])) + "\n")

    run_info = OrderedDict([
        ("command", "python3 run_pilot.py"),
        ("run_at_utc", datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")),
        ("python_version", sys.version.split()[0]), ("python_implementation", platform.python_implementation()),
        ("platform", platform.platform()),
        ("fixture_version", manifest["fixture_version"]), ("sanity_seed", manifest["sanity_seed"]),
        ("call_order_seeds", list(ORDER_SEEDS)),
        ("sha256", OrderedDict((f, sha256_file(ROOT / f)) for f in FROZEN_FILES)),
        ("freeze", frz),
        ("reviewer_isolation", "per call: fresh temporary directory containing only a copy of reviewer.py; "
                               "python3 -I; env={}; input on stdin only; seeded shuffled call order. "
                               "Process-level isolation, not an OS sandbox."),
        ("passes", 2),
    ])
    write_text(out / "run_info.json", dump_json(run_info))

    # ---- console report
    print("Redaction audit pilot | fixtures v%s | Python %s | %d runs, %d pairs"
          % (manifest["fixture_version"], sys.version.split()[0], len(cases), len(cases) // 2))
    print("Freeze: %s" % ("matches FREEZE.json entry %s" % frz["label"] if frz["matches"] else
                          ("NOT FROZEN" if not frz["frozen"] else
                           "MISMATCH with %s %s %s (not a frozen run)" % (frz["label"], frz["mismatched"],
                                                                         frz.get("not_covered")))))
    print()
    fmt = "%-16s %-11s %-9s %-11s %-8s %-7s %-7s %-8s %-9s %s"
    print(fmt % ("view", "ident.pairs", "R/D/E/V", "ceiling", "correct", "missed", "f.alarm", "abstain",
                 "coverage", "exposed"))
    for f in flat:
        rdev = "/".join(f["identical_" + k].split("/")[0] for k in ("recipient", "document", "expiry", "revocation"))
        print(fmt % (f["view"], f["identical_pairs"], rdev, "%s=%.2f" % (f["ceiling"], f["ceiling_value"]),
                     f["correct"], f["missed_violations"], f["false_alarms"], f["abstentions"],
                     f["definitive_coverage"], f["exposure_distinct"]))
    nv = supplementary["B_naive_mask_equality"]["metric3_reviewer"]
    print(fmt % ("B_naive (supp.)", "", "", "", show(nv["correct"]), show(nv["missed_violations"]),
                 show(nv["false_alarms"]), show(nv["abstentions"]), show(nv["definitive_coverage"]), ""))
    print("\nR/D/E/V = identical pairs by family (of 4/2/2/2). missed = of 10 unauthorised; "
          "f.alarm = of 10 authorised; exposed = distinct planted values visible.")
    print("Shared-timeline variant (supp.): " + "; ".join(
        "%s ceiling %s, %s distinct inputs, correct %s" % (v, d["ceiling"], d["distinct_inputs"], d["reviewer_correct"])
        for v, d in shared.items()))
    n_ok = sum(c["ok"] for c in checks)
    print("\nValidation: %d/%d checks passed%s" % (n_ok, len(checks), "" if n_ok == len(checks) else ":"))
    for c in checks:
        if not c["ok"]:
            print("  FAIL", c["check"], c["detail"])
    print("Results written to %s" % out)
    return 0 if n_ok == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
