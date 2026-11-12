"""Boundary and transformation tests (standard-library unittest).

Run: python3 -m unittest discover -s tests -t .
"""
import copy
import json
import unittest

from pilot import exposure, fixtures, policy, reviewer, views


def make(**over):
    spec = dict(grant_doc="D1", grant_rcp="A", purpose="case review", grant_time=10, expires_at=30,
                revocation=fixtures.NOT_REVOKED, share_time=20, share_doc="D1", share_rcp="A",
                message="Test message, ref ZZ-00-TT.")
    spec.update(over)
    return fixtures._record("T-" + json.dumps(over, sort_keys=True), spec)


def review(view, record, naive=False):
    return reviewer.review(json.loads(views.render(view, record)), naive_masks=naive)


class PolicyBoundaries(unittest.TestCase):
    def verdict(self, **over):
        return policy.evaluate(make(**over))

    def test_share_at_grant_time_is_allowed(self):
        self.assertEqual(self.verdict(share_time=10)["verdict"], "authorised")

    def test_share_before_grant_fails(self):
        self.assertEqual(self.verdict(share_time=9)["failed"], ["before_grant"])

    def test_share_exactly_at_expiry_fails(self):
        self.assertEqual(self.verdict(share_time=30)["failed"], ["expired"])

    def test_share_just_before_expiry_passes(self):
        self.assertEqual(self.verdict(share_time=29)["verdict"], "authorised")

    def test_revocation_exactly_at_share_fails(self):
        self.assertEqual(self.verdict(revocation=fixtures.revoked(20))["failed"], ["revoked"])

    def test_revocation_after_share_passes(self):
        self.assertEqual(self.verdict(revocation=fixtures.revoked(21))["verdict"], "authorised")

    def test_purpose_mismatch_fails(self):
        rec = make()
        rec["events"][1]["purpose"] = "marketing"
        self.assertEqual(policy.evaluate(rec)["failed"], ["purpose_mismatch"])


class ReviewerRules(unittest.TestCase):
    def test_full_view_matches_policy_on_boundaries(self):
        for over in [dict(share_time=10), dict(share_time=9), dict(share_time=30),
                     dict(revocation=fixtures.revoked(20)), dict(share_rcp="B"), dict(share_doc="D2")]:
            rec = make(**over)
            self.assertEqual(review("A_full", rec)["verdict"], policy.evaluate(rec)["verdict"], over)

    def test_uniform_mask_is_unknown_even_when_equal(self):
        out = review("B_uniform_mask", make())
        self.assertEqual(out["checks"]["recipient_matches"], "unknown")
        self.assertEqual(out["verdict"], "insufficient_evidence")

    def test_known_timing_failure_establishes_violation_under_masking(self):
        self.assertEqual(review("B_uniform_mask", make(share_time=30))["verdict"], "unauthorised")

    def test_alias_mismatch_is_a_known_failure(self):
        out = review("C_alias", make(share_rcp="B"))
        self.assertEqual(out["checks"]["recipient_matches"], "fail")
        self.assertEqual(out["verdict"], "unauthorised")

    def test_missing_expiry_is_unknown(self):
        out = review("C_no_expiry", make())
        self.assertEqual(out["checks"]["before_expiry"], "unknown")
        self.assertEqual(out["verdict"], "insufficient_evidence")

    def test_missing_revocation_is_unknown_but_explicit_absence_passes(self):
        self.assertEqual(review("C_no_revocation", make())["checks"]["not_revoked"], "unknown")
        self.assertEqual(review("C_alias", make())["checks"]["not_revoked"], "pass")

    def test_purpose_mismatch_is_a_known_failure_in_every_view(self):
        rec = make()
        rec["events"][1]["purpose"] = "marketing"
        for v in ("A_full", "B_uniform_mask", "C_alias", "C_no_expiry", "C_no_revocation"):
            out = review(v, rec)
            self.assertEqual(out["checks"]["purpose_matches"], "fail", v)
            self.assertEqual(out["verdict"], "unauthorised", v)

    def test_grant_time_boundary_in_masked_and_aliased_views(self):
        for v in ("B_uniform_mask", "C_alias"):
            self.assertEqual(review(v, make(share_time=9))["verdict"], "unauthorised", v)
            self.assertEqual(review(v, make(share_time=10))["checks"]["at_or_after_grant"], "pass", v)
        self.assertEqual(review("C_alias", make(share_time=10))["verdict"], "authorised")

    def test_naive_mode_treats_equal_masks_as_match(self):
        self.assertEqual(review("B_uniform_mask", make(share_rcp="B"), naive=True)["verdict"], "authorised")


class ViewTransforms(unittest.TestCase):
    def test_alias_first_appearance_and_separate_namespaces(self):
        rec = make(share_rcp="B", share_doc="D2")
        g, s = json.loads(views.render("C_alias", rec))["events"]
        self.assertEqual((g["document"]["id"], g["recipient"]["id"]), ("DOC_ALIAS_1", "RCP_ALIAS_1"))
        self.assertEqual((s["document"]["id"], s["recipient"]["id"]), ("DOC_ALIAS_2", "RCP_ALIAS_2"))

    def test_aliases_reset_per_run(self):
        # Render a run that uses two aliases, then a different run: numbering must restart.
        first = json.loads(views.render("C_alias", make(share_rcp="B", share_doc="D2")))
        self.assertEqual(first["events"][1]["recipient"]["id"], "RCP_ALIAS_2")
        second = json.loads(views.render("C_alias", make(grant_rcp="B", share_rcp="A",
                                                         grant_doc="D2", share_doc="D1")))
        self.assertEqual(second["events"][0]["recipient"]["id"], "RCP_ALIAS_1")
        self.assertEqual(second["events"][0]["document"]["id"], "DOC_ALIAS_1")
        self.assertEqual(second["events"][1]["recipient"]["id"], "RCP_ALIAS_2")

    def test_masked_views_hide_every_private_field(self):
        rec = make(share_rcp="B")
        for v in ("B_uniform_mask", "C_alias", "C_no_expiry", "C_no_revocation"):
            b = views.render(v, rec)
            self.assertEqual(exposure.visible_values(b, exposure.planted_values(rec)), [], v)

    def test_views_keep_policy_facts_and_order(self):
        rec = make()
        for v in ("A_full", "B_uniform_mask", "C_alias"):
            g, s = json.loads(views.render(v, rec))["events"]
            self.assertEqual((g["event"], s["action"]), ("consent_grant", "share_document"))
            self.assertEqual((g["time"], g["expires_at"], s["time"], g["purpose"]), (10, 30, 20, "case review"))

    def test_ablations_remove_only_their_field(self):
        rec = make()
        full_c = json.loads(views.render("C_alias", rec))
        no_exp = json.loads(views.render("C_no_expiry", rec))
        no_rev = json.loads(views.render("C_no_revocation", rec))
        expected = copy.deepcopy(full_c)
        del expected["events"][0]["expires_at"]
        self.assertEqual(no_exp, expected)
        expected = copy.deepcopy(full_c)
        del expected["events"][0]["revocation"]
        self.assertEqual(no_rev, expected)

    def test_view_drops_case_and_run_ids(self):
        b = views.render("A_full", make())
        self.assertEqual(set(json.loads(b)), {"events"})
        self.assertNotIn(b"run-", b)


class StaticIsolationCheck(unittest.TestCase):
    def test_allowlist_rejects_indirect_file_access(self):
        import os
        import tempfile
        from pilot import validate
        src = open(os.path.join(os.path.dirname(reviewer.__file__), "reviewer.py")).read()
        cheat = src.replace("    raw = sys.stdin.buffer.read()",
                            "    raw = sys.stdin.buffer.read()\n    json.codecs.open('data/manifest.json')")
        self.assertNotEqual(src, cheat)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "reviewer.py")
            with open(path, "w") as fh:
                fh.write(cheat)
            results = {r["check"]: r["ok"] for r in validate.check_reviewer_static(path)}
        self.assertFalse(results["reviewer_attribute_allowlist"])

    def test_real_reviewer_passes_allowlist(self):
        import os
        from pilot import validate
        path = os.path.join(os.path.dirname(reviewer.__file__), "reviewer.py")
        self.assertTrue(all(r["ok"] for r in validate.check_reviewer_static(path)))


class Scanner(unittest.TestCase):
    def test_scanner_matches_json_escaped_form(self):
        self.assertEqual(exposure.visible_values(b'{"x":"col1\\tcol2"}', {"col1\tcol2": "content"}),
                         ["col1\tcol2"])


if __name__ == "__main__":
    unittest.main()
