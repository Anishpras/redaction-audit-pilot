#!/usr/bin/env python3
"""Template for your own reviewer (for example an LLM), used with --reviewer "exec:python3 reviewer_template.py".

Protocol: stdin is {"policy": {...}, "log": {...}}; print {"verdict": "authorised" | "unauthorised" |
"insufficient_evidence", "checks": {condition_id: "pass" | "fail" | "unknown"}} on stdout. "checks" is
optional but lets the tool attribute errors to conditions. The process runs in an empty temporary
directory with a minimal environment; pass variables it needs with --reviewer-env NAME.

This placeholder abstains on everything. Replace review() with a call to your model, prompted with
the policy and the redacted log.
"""
import json
import sys


def review(policy, log):
    return {"verdict": "insufficient_evidence",
            "checks": {c["id"]: "unknown" for c in policy["conditions"]}}


request = json.load(sys.stdin)
json.dump(review(request["policy"], request["log"]), sys.stdout)
