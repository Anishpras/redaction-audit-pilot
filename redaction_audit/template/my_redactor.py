#!/usr/bin/env python3
"""Example external redactor for the 'exec' op. Replace the body with a call to your real redactor.

Protocol: read {"events": [...]} on stdin and print {"events": [...], "declarations": {...}} on stdout.
"declarations" is optional: path -> {"method": "mask"|"alias"|"pseudonym"|"drop"|"bucket"|"rank", ...}.

This example behaves like many real tools: it replaces customer ids and names with a type label
("<CUSTOMER>") and declares nothing. Run the audit and look at the my_redactor column of matrix.md:
an undeclared constant label is read as a real identifier, so every misdirected read looks
authorised (UNSAFE). Adding "declarations": {"attributes.customer_id": {"method": "mask"}}
turns that into an honest "unverifiable".
"""
import json
import sys

log = json.load(sys.stdin)
for event in log["events"]:
    attrs = event.get("attributes", {})
    for key, label in (("customer_id", "<CUSTOMER>"), ("customer_name", "<PERSON>"),
                       ("result_excerpt", "<TEXT>"), ("prompt_summary", "<TEXT>")):
        if key in attrs:
            attrs[key] = label
json.dump({"events": log["events"]}, sys.stdout)
