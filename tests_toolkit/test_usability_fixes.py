"""Regression tests for the problems found by the newcomer usability test (v1.2)."""
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

POLICY = {
    "name": "Payment test policy",
    "subject": "payment",
    "roles": {"approval": {"where": {"type": "approval"}}, "payment": {"where": {"type": "payment"}}},
    "conditions": [
        {"id": "same_payee", "need": "equality", "left": "approval.payee", "right": "payment.payee"},
        {"id": "four_eyes", "need": "equality", "relation": "different",
         "left": "approval.approver", "right": "payment.requester"},
        {"id": "within_amount", "need": "order", "left": "payment.amount", "op": "<=", "right": "approval.amount"},
        {"id": "before_expiry", "need": "order", "left": "payment.time", "op": "<", "right": "approval.expires_at"},
    ],
}


def base(case_id="b1", payee="DE89370400440532013000", amount=1250.50, time=100):
    return {"case_id": case_id, "log": {"events": [
        {"type": "approval", "payee": payee, "approver": "mgr-ana", "amount": amount, "expires_at": 200},
        {"type": "payment", "payee": payee, "requester": "clerk-bo", "amount": amount, "time": time}]}}


FIELDS = {"private": [{"path": "payee", "category": "identifier"},
                      {"path": "approver", "category": "identifier"},
                      {"path": "requester", "category": "identifier"},
                      {"path": "amount", "category": "amount"}],
          "times": ["time", "expires_at"]}


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, policy=POLICY, fields=FIELDS, records=None, views=None):
        (self.tmp / "p.json").write_text(json.dumps(policy))
        (self.tmp / "f.json").write_text(json.dumps(fields))
        (self.tmp / "c.jsonl").write_text("\n".join(json.dumps(r) for r in (records or [base()])))
        (self.tmp / "v.json").write_text(json.dumps(views or {"views": [{"name": "full", "ops": []}]}))
        return [str(self.tmp / n) for n in ("p.json", "f.json", "c.jsonl", "v.json")]

    def run_quiet(self, *args, **kw):
        with contextlib.redirect_stdout(io.StringIO()):
            return run.run(*args, quiet=True, **kw)


class StrictValidation(Tmp):
    def test_unknown_key_is_an_error_not_ignored(self):
        bad = json.loads(json.dumps(POLICY))
        bad["conditions"][1] = {"id": "four_eyes", "need": "equality", "op": "!=",
                                "left": "approval.approver", "right": "payment.requester"}
        with self.assertRaises(spec.SpecError) as ctx:
            spec.check_policy(bad)
        self.assertIn("unknown key 'op'", str(ctx.exception))

    def test_selector_typo_is_an_error_with_hint(self):
        p = self.write(views={"views": [{"name": "v", "ops": [{"op": "mask", "fields": ["identifiers"]}]}]})
        with self.assertRaises(spec.SpecError) as ctx:
            self.run_quiet(*p, str(self.tmp / "out"))
        self.assertIn("did you mean 'identifier'", str(ctx.exception))

    def test_iso_timestamp_gives_a_precise_message(self):
        rec = base()
        rec["log"]["events"][1]["time"] = "2026-11-12T10:00:00Z"
        with self.assertRaises(ValueError) as ctx:
            evaluate.reference(POLICY, rec["log"])
        self.assertIn("epoch seconds", str(ctx.exception))

    def test_role_matching_two_events_is_explained(self):
        rec = base()
        rec["log"]["events"].append(dict(rec["log"]["events"][1]))
        with self.assertRaises(ValueError) as ctx:
            evaluate.reference(POLICY, rec["log"])
        self.assertIn("matched 2 events", str(ctx.exception))


class Expressiveness(unittest.TestCase):
    def test_decimal_amounts_and_four_eyes(self):
        verdict, failed = evaluate.reference(POLICY, base()["log"])
        self.assertEqual((verdict, failed), ("authorised", []))
        runs, pairs, mode = cases.load(POLICY, [base()])
        self.assertEqual(len(pairs), 4)
        four_eyes = next(p for p in pairs if p["target"] == "four_eyes")
        ev = runs[four_eyes["unauth"]]["log"]["events"]
        self.assertEqual(ev[0]["approver"], ev[1]["requester"])  # default violation: same person

    def test_format_preserving_violation_keeps_the_ending(self):
        runs, pairs, _ = cases.load(POLICY, [base()])
        p = next(p for p in pairs if p["target"] == "same_payee")
        payee = runs[p["unauth"]]["log"]["events"][1]["payee"]
        self.assertNotEqual(payee, "DE89370400440532013000")
        self.assertEqual(len(payee), 22)
        self.assertEqual(payee[-4:], "3000")

    def test_partial_masking_semantics(self):
        d = {"payee": {"method": "partial", "keep_last": 4}}
        log = {"events": [{"type": "approval", "payee": "****3000", "approver": "a", "amount": 1, "expires_at": 9},
                          {"type": "payment", "payee": "****3000", "requester": "b", "amount": 1, "time": 1}],
               "redaction": d}
        self.assertEqual(evaluate.evaluate(POLICY, log)["checks"]["same_payee"], "unknown")
        self.assertEqual(evaluate.evaluate(POLICY, log, declared=False)["checks"]["same_payee"], "pass")
        log["events"][1]["payee"] = "****4000"
        self.assertEqual(evaluate.evaluate(POLICY, log)["checks"]["same_payee"], "fail")

    def test_partial_redaction_is_caught_as_unsafe_when_undeclared(self):
        policy = POLICY
        runs, pairs, _ = cases.load(policy, [base()])
        view = {"ops": [{"op": "partial", "fields": ["payee"], "keep_last": 4}], "declare": False}
        p = next(p for p in pairs if p["target"] == "same_payee")
        b = transforms.render(view, "r", runs[p["unauth"]]["log"], FIELDS)
        self.assertEqual(evaluate.evaluate(policy, json.loads(b))["verdict"], "authorised")  # misled

    def test_case_decoys_and_several_mutations(self):
        policy = json.loads(json.dumps(POLICY))
        policy["conditions"][0]["mutate"] = [{"set": {"payment.payee": {"decoy": "lookalike"}}}]
        policy["conditions"][3]["mutations"] = [
            [{"set": {"approval.expires_at": {"copy": "payment.time"}}}],
            [{"set": {"approval.expires_at": {"add": ["payment.time", -50]}}}]]
        rec = base()
        rec["decoys"] = {"lookalike": "DE00000000000000003000"}
        runs, pairs, _ = cases.load(policy, [rec])
        payee_pair = next(p for p in pairs if p["target"] == "same_payee")
        self.assertEqual(runs[payee_pair["unauth"]]["log"]["events"][1]["payee"], "DE00000000000000003000")
        self.assertEqual(sum(p["target"] == "before_expiry" for p in pairs), 2)

    def test_mixed_explicit_and_generated_cases(self):
        auth = dict(base("x-auth"), pair_id="x", family="manual", label="authorised")
        un = base("x-unauth", amount=1250.50)
        un["log"]["events"][1]["amount"] = 9999.0
        un.update(pair_id="x", family="manual", label="unauthorised")
        runs, pairs, mode = cases.load(POLICY, [auth, un, base("b2")])
        self.assertEqual(mode, "mixed")
        self.assertEqual(len(pairs), 1 + 4)


class Outputs(Tmp):
    def test_exposure_by_field_and_exposure_gate(self):
        views = {"views": [{"name": "full", "ops": []},
                           {"name": "ids_masked", "ops": [{"op": "mask", "fields": ["identifier"]}]}]}
        p = self.write(views=views, records=[base("b1"), base("b2", payee="FR7630006000011234567890189")])
        code = self.run_quiet(*p, str(self.tmp / "o"), fail_on=("exposed",), gate=["ids_masked"])
        self.assertEqual(code, 1)  # amounts were not masked
        with open(self.tmp / "o" / "exposure.csv") as fh:
            rows = list(csv.DictReader(fh))
        amount = next(r for r in rows if r["view"] == "ids_masked" and r["field"] == "amount")
        self.assertEqual(amount["visible"], amount["distinct_values"])
        self.assertTrue((self.tmp / "o" / "readings.csv").exists())

    def test_matrix_names_the_cases_behind_problems(self):
        views = {"views": [{"name": "masked", "ops": [{"op": "mask", "fields": ["identifier"]}]}]}
        p = self.write(views=views)
        self.run_quiet(*p, str(self.tmp / "o"))
        text = (self.tmp / "o" / "matrix.md").read_text()
        self.assertIn("b1~same_payee", text)

    def test_cli_gate_accepts_comma_list(self):
        views = {"views": [{"name": "a", "ops": []}, {"name": "b", "ops": []}]}
        p = self.write(views=views)
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["run", "--policy", p[0], "--fields", p[1], "--cases", p[2], "--views", p[3],
                             "--out", str(self.tmp / "o"), "--fail-on", "unsafe,unverifiable", "--gate", "a,b"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
