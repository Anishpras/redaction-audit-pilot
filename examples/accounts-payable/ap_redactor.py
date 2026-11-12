#!/usr/bin/env python3
# Written by an AI agent acting as a first-time user during the v1.2 usability test, as a stand-in for a
# real in-house regex redactor. Kept unchanged as a realistic example of an undeclared transformation.
"""Stand-in for our in-house AP log redactor, wrapped for redaction_audit's exec op.

What it does (mirrors the production regex scrubber):
  - IBANs anywhere in a string -> "IBAN-****" + last 4 characters (finance asked to keep the last 4)
  - employee ids (emp-NNNNN)   -> "emp#" + first 8 hex chars of an unsalted SHA-256 (stable across runs)
  - actor.name, payload.vendor_name -> "[REDACTED]"
  - invoice ids inside free text -> "[INV]"; the payload.invoice_id field itself is kept (finance needs it)
  - all timestamps floored to the minute
It declares the employee hashing and the time flooring, but not the IBAN truncation (the old
scrubber never emitted a header for it).
"""
import hashlib
import json
import re
import sys

IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
EMP = re.compile(r"\bemp-\d{5}\b")
INV = re.compile(r"\bINV-\d{4}-\d{5}\b")
TIME_KEYS = {("ts",), ("payload", "expires_at"), ("payload", "withdrawn_at")}
FREE_TEXT = {"memo", "comment", "prompt_summary", "invoice_doc_ref"}


def scrub(s, free_text):
    s = IBAN.sub(lambda m: "IBAN-****" + m.group(0)[-4:], s)
    s = EMP.sub(lambda m: "emp#" + hashlib.sha256(m.group(0).encode()).hexdigest()[:8], s)
    if free_text:
        s = INV.sub("[INV]", s)
    return s


def walk(obj, path=()):
    if isinstance(obj, dict):
        for k in list(obj):
            p = path + (k,)
            v = obj[k]
            if p in TIME_KEYS and isinstance(v, int):
                obj[k] = v - v % 60
            elif k in ("name", "vendor_name") and isinstance(v, str):
                obj[k] = "[REDACTED]"
            elif isinstance(v, str):
                obj[k] = scrub(v, k in FREE_TEXT)
            else:
                walk(v, p)
    elif isinstance(obj, list):
        for x in obj:
            walk(x, path)


log = json.load(sys.stdin)
walk(log["events"])
declarations = {
    "actor.id": {"method": "pseudonym", "scope": "global"},
    "payload.requested_by": {"method": "pseudonym", "scope": "global"},
    "ts": {"method": "bucket", "size": 60},
    "payload.expires_at": {"method": "bucket", "size": 60},
    "payload.withdrawn_at": {"method": "bucket", "size": 60},
}
json.dump({"events": log["events"], "declarations": declarations}, sys.stdout)
