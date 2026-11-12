"""Tests for the reusable toolkit.  Run: python3 -m unittest discover -s tests_toolkit -t ."""
import contextlib
import csv
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from redaction_audit import __main__ as cli
from redaction_audit import cases, evaluate, run, spec, transforms

ROOT = Path(__file__).resolve().parent.parent
PILOT = ROOT / "examples" / "consent-share"
TEMPLATE = ROOT / "redaction_audit" / "template"


def run_quiet(*args, **kw):
    with contextlib.redirect_stdout(io.StringIO()):
        return run.run(*args, quiet=True, **kw)


def summary_rows(out):
    with open(out / "summary.csv") as fh:
        return {r["view"]: r for r in csv.DictReader(fh)}


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class PilotReproduction(TempDirCase):
    def test_reproduces_pilot_tables_byte_for_byte(self):
        out = self.tmp / "out"
        code = run_quiet(PILOT / "policy.json", PILOT / "fields.json", PILOT / "cases.jsonl",
                         PILOT / "views.json", out)
        self.assertEqual(code, 0)
        for name in ("summary.csv", "family_breakdown.csv"):
            self.assertEqual((out / name).read_bytes(), (ROOT / "results" / name).read_bytes(), name)

    def test_extended_views_declared_and_undeclared(self):
        args = (PILOT / "policy.json", PILOT / "fields.json", PILOT / "cases.jsonl", PILOT / "views_extended.json")
        run_quiet(*args, self.tmp / "d", reviewer="builtin")
        run_quiet(*args, self.tmp / "u", reviewer="undeclared")
        d, u = summary_rows(self.tmp / "d"), summary_rows(self.tmp / "u")
        # per-event pseudonyms: perfect-looking ceiling, but undeclared review flags every authorised share
        self.assertEqual(d["D_pseudonym_event"]["ceiling"], "20/20")
        self.assertEqual(u["D_pseudonym_event"]["false_alarms"], "10/10")
        self.assertEqual(d["D_pseudonym_event"]["false_alarms"], "0/10")
        # uniform masks read naively reproduce the pilot's naive diagnostic
        self.assertEqual((u["B_uniform_mask"]["correct"], u["B_uniform_mask"]["missed_violations"]), ("14/20", "6/10"))
        # bucketed times: declared review abstains at the boundary, undeclared review is wrong there
        self.assertEqual(u["G_times_bucket10"]["false_alarms"], "2/10")
        self.assertEqual(d["G_times_bucket10"]["false_alarms"], "0/10")
        # equality-preserving choices keep every verdict
        for v in ("E_pseudonym_run", "F_pseudonym_global", "H_times_rank"):
            self.assertEqual(d[v]["correct"], "20/20", v)


class GeneratedPairs(TempDirCase):
    def test_template_generates_one_boundary_violation_per_condition(self):
        policy = spec.check_policy(spec.load_json(TEMPLATE / "policy.json"))
        runs, pairs, mode = cases.load(policy, spec.load_jsonl(TEMPLATE / "cases.jsonl"))
        self.assertEqual(mode, "generated")
        self.assertEqual(len(pairs), 6 * len(policy["conditions"]))
        for p in pairs:
            verdict, failed = evaluate.reference(policy, runs[p["unauth"]]["log"])
            self.assertEqual((verdict, failed), (evaluate.UNAUTH, [p["target"]]))

    def test_gate_fails_on_unsafe_custom_redactor_and_passes_on_aliases(self):
        args = (TEMPLATE / "policy.json", TEMPLATE / "fields.json", TEMPLATE / "cases.jsonl", TEMPLATE / "views.json")
        self.assertEqual(run_quiet(*args, self.tmp / "a", fail_on=("unsafe",), gate=["my_redactor"]), 1)
        self.assertEqual(run_quiet(*args, self.tmp / "b", fail_on=("unsafe", "unverifiable"),
                                   gate=["alias_per_run", "hash_per_run", "times_rank"]), 0)

    def test_mutation_that_breaks_two_conditions_is_rejected(self):
        policy = spec.check_policy(spec.load_json(TEMPLATE / "policy.json"))
        policy["conditions"][0]["mutate"] = [{"set": {"call.attributes.agent_id": "someone-else",
                                                      "call.attributes.agent_role": "intern"}}]
        with self.assertRaises(spec.SpecError):
            cases.load(policy, spec.load_jsonl(TEMPLATE / "cases.jsonl"))


class AccountsPayableExample(TempDirCase):
    def test_proposed_design_is_verifiable_and_hides_everything(self):
        X = ROOT / "examples" / "accounts-payable"
        run_quiet(X / "policy.json", X / "fields.json", X / "cases.jsonl", X / "views.json", self.tmp / "o")
        with open(self.tmp / "o" / "readings.csv") as fh:
            readings = list(csv.DictReader(fh))
        ranked = [r for r in readings if r["view"] == "prod_proposed_amounts_ranked"]
        self.assertTrue(ranked and all(r["declared"] == r["undeclared"] == "verified" for r in ranked))
        rows = summary_rows(self.tmp / "o")
        self.assertEqual(rows["prod_proposed_amounts_ranked"]["exposure_distinct"], "0/81")
        self.assertTrue(any(r["view"] == "ap_redactor" and r["condition"] == "payee_checked"
                            and r["declared"] == "unsafe" for r in readings))


class ReviewerSemantics(unittest.TestCase):
    POLICY = {"roles": {"a": {"where": {"k": "a"}}, "b": {"where": {"k": "b"}}},
              "conditions": [{"id": "eq", "need": "equality", "left": "a.x", "right": "b.x"},
                             {"id": "lt", "need": "order", "left": "b.t", "op": "<", "right": "a.t"},
                             {"id": "here", "need": "presence", "field": "a.flag"}]}

    def check(self, events, redaction=None, declared=True):
        log = {"events": events}
        if redaction:
            log["redaction"] = redaction
        return evaluate.evaluate(self.POLICY, log, declared=declared)["checks"]

    def test_bucket_intervals(self):
        ev = [{"k": "a", "x": 1, "t": 30, "flag": 1}, {"k": "b", "x": 1, "t": 20}]
        r = {"t": {"method": "bucket", "size": 10}}
        self.assertEqual(self.check(ev, r)["lt"], "pass")          # [20,29] < [30,39]
        ev[1]["t"] = 30
        self.assertEqual(self.check(ev, r)["lt"], "unknown")       # same bucket
        self.assertEqual(self.check(ev, r, declared=False)["lt"], "fail")  # literal reading

    def test_pseudonym_scope(self):
        ev = [{"k": "a", "x": "P1", "t": 2, "flag": 1}, {"k": "b", "x": "P2", "t": 1}]
        self.assertEqual(self.check(ev, {"x": {"method": "pseudonym", "scope": "event"}})["eq"], "unknown")
        self.assertEqual(self.check(ev, {"x": {"method": "pseudonym", "scope": "run"}})["eq"], "fail")
        self.assertEqual(self.check(ev, {"x": {"method": "mask"}})["eq"], "unknown")

    def test_presence_declared_drop_is_unknown_not_fail(self):
        ev = [{"k": "a", "x": 1, "t": 2}, {"k": "b", "x": 1, "t": 1}]
        self.assertEqual(self.check(ev, {"flag": {"method": "drop"}})["here"], "unknown")
        self.assertEqual(self.check(ev)["here"], "fail")

    def test_rank_preserves_order(self):
        ev = [{"k": "a", "x": 1, "t": 2, "flag": 1}, {"k": "b", "x": 1, "t": 1}]
        self.assertEqual(self.check(ev, {"t": {"method": "rank", "group": "times"}})["lt"], "pass")

    def test_role_not_found_is_unknown(self):
        self.assertEqual(self.check([{"k": "a", "x": 1, "t": 2, "flag": 1}])["eq"], "unknown")


class TransformsAndCli(TempDirCase):
    def test_pseudonym_event_scope_differs_across_events(self):
        fields = {"private": [{"path": "x", "category": "identifier"}]}
        log = {"events": [{"x": "same"}, {"x": "same"}]}
        v = transforms.apply_view({"ops": [{"op": "pseudonym", "fields": ["identifier"], "scope": "event"}]},
                                  "r1", log, fields)
        self.assertNotEqual(v["events"][0]["x"], v["events"][1]["x"])
        v = transforms.apply_view({"ops": [{"op": "pseudonym", "fields": ["identifier"], "scope": "run"}]},
                                  "r1", log, fields)
        self.assertEqual(v["events"][0]["x"], v["events"][1]["x"])

    def test_views_never_contain_case_ids(self):
        log = {"events": [{"x": "v"}]}
        b = transforms.render({"ops": []}, "secret-case-id", log, {"private": []})
        self.assertNotIn(b"secret-case-id", b)

    def test_exec_reviewer_protocol(self):
        args = (TEMPLATE / "policy.json", TEMPLATE / "fields.json", TEMPLATE / "cases.jsonl", TEMPLATE / "views.json")
        run_quiet(*args, self.tmp / "o", reviewer="exec:python3 %s" % (TEMPLATE / "reviewer_template.py"))
        rows = summary_rows(self.tmp / "o")
        self.assertEqual(rows["full"]["abstentions"], "42/42")

    def test_cli_init_and_bad_policy(self):
        dest = self.tmp / "audit"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["init", str(dest)]), 0)
        self.assertTrue((dest / "policy.json").exists())
        bad = self.tmp / "bad.json"
        bad.write_text(json.dumps({"roles": {}, "conditions": [{"id": "x", "need": "vibes"}]}))
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(["checklist", "--policy", str(bad)]), 2)
        self.assertIn("need", err.getvalue())

    def test_checklist_lists_every_condition(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            cli.main(["checklist", "--policy", str(TEMPLATE / "policy.json")])
        for cond in spec.load_json(TEMPLATE / "policy.json")["conditions"]:
            self.assertIn(cond["id"], out.getvalue())


if __name__ == "__main__":
    unittest.main()
