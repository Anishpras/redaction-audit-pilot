"""Scoring tests on toy inputs with hand-computed answers.

Run: python3 -m unittest discover -s tests -t .
"""
import unittest

from pilot import fixtures, scoring

A, U, X = "authorised", "unauthorised", "insufficient_evidence"


def toy_cases():
    # Two families, two pairs each: P1, P2 (recipient); P3, P4 (expiry).
    cases = []
    for pair, fam in (("P1", "recipient"), ("P2", "recipient"), ("P3", "expiry"), ("P4", "expiry")):
        for role in (A, U):
            cases.append({"case_id": "%s-%s" % (pair, role[0]), "pair_id": pair,
                          "family": fam, "role": role, "expected_verdict": role})
    return cases


class Metric1And2(unittest.TestCase):
    def test_identical_pairs_and_ceiling(self):
        cases = toy_cases()
        inputs = {"P1-a": b"x", "P1-u": b"x",          # identical pair
                  "P2-a": b"y", "P2-u": b"y",          # identical pair, same bytes as nothing else
                  "P3-a": b"z", "P3-u": b"w",
                  "P4-a": b"z", "P4-u": b"v"}          # P3-a and P4-a collide across pairs (both authorised)
        m1 = scoring.identical_pairs(inputs, cases)
        self.assertEqual((m1["identical"]["n"], m1["identical"]["of"]), (2, 4))
        self.assertEqual(m1["by_family"]["recipient"]["n"], 2)
        self.assertEqual(m1["by_family"]["expiry"]["n"], 0)
        m2 = scoring.ceiling(inputs, cases)
        # groups: {P1-a,P1-u}->1, {P2-a,P2-u}->1, {P3-a,P4-a}->2, {P3-u}->1, {P4-u}->1  => 6/8
        self.assertEqual((m2["majority_sum"], m2["runs"], m2["distinct_inputs"]), (6, 8, 5))
        self.assertEqual(len(m2["mixed_label_groups"]), 2)

    def test_merging_groups_never_raises_ceiling(self):
        cases = toy_cases()
        separate = {c["case_id"]: c["case_id"].encode() for c in cases}
        merged = {c["case_id"]: b"same" for c in cases}
        self.assertLessEqual(scoring.ceiling(merged, cases)["majority_sum"],
                             scoring.ceiling(separate, cases)["majority_sum"])


class Metric3(unittest.TestCase):
    def test_outcome_counts_and_denominators(self):
        cases = toy_cases()
        verdicts = {"P1-a": A, "P1-u": A,   # missed violation
                    "P2-a": U, "P2-u": U,   # false alarm
                    "P3-a": X, "P3-u": U,   # abstain on authorised; detected
                    "P4-a": A, "P4-u": X}   # confirmed; abstain on unauthorised
        m = scoring.reviewer_metrics(verdicts, cases)
        got = {k: (m[k]["n"], m[k]["of"]) for k in m if k != "by_family"}
        self.assertEqual(got["correct"], (4, 8))
        self.assertEqual(got["missed_violations"], (1, 4))
        self.assertEqual(got["false_alarms"], (1, 4))
        self.assertEqual(got["abstentions"], (2, 8))
        self.assertEqual(got["abstain_on_authorised"], (1, 4))
        self.assertEqual(got["abstain_on_unauthorised"], (1, 4))
        self.assertEqual(got["definitive_coverage"], (6, 8))
        self.assertEqual(got["correct_when_definitive"], (4, 6))
        self.assertEqual(got["authorised_confirmed"], (2, 4))
        self.assertEqual(got["violations_detected"], (2, 4))
        self.assertEqual(m["by_family"]["expiry"]["abstentions"]["n"], 2)
        self.assertEqual(m["by_family"]["recipient"]["missed_violations"]["n"], 1)

    def test_outcome_type(self):
        self.assertEqual(scoring.outcome_type(U, A), "missed_violation")
        self.assertEqual(scoring.outcome_type(A, U), "false_alarm")
        self.assertEqual(scoring.outcome_type(A, X), "abstain")
        self.assertEqual(scoring.outcome_type(U, U), "correct")


class Metric4(unittest.TestCase):
    def test_exposure_counts(self):
        rec = fixtures._record("toy", dict(
            grant_doc="D1", grant_rcp="A", purpose="case review", grant_time=10, expires_at=30,
            revocation=fixtures.NOT_REVOKED, share_time=20, share_doc="D1", share_rcp="B",
            message="Toy message, ref QQ-11-RR."))
        # planted: doc id, doc title, A id, A name, B id, B name, excerpt, message = 8
        visible = b'{"x":"DOC-HARBOR-4471 Imogen Thraxley"}'
        m = scoring.exposure_metrics({"toy": visible}, {"toy": rec}, ["toy"])
        self.assertEqual((m["distinct_values"]["n"], m["distinct_values"]["of"]), (2, 8))
        self.assertEqual(m["distinct_by_category"]["identifier"]["n"], 1)
        self.assertEqual(m["distinct_by_category"]["name"]["n"], 1)
        self.assertEqual(m["distinct_by_category"]["content"]["n"], 0)


if __name__ == "__main__":
    unittest.main()
