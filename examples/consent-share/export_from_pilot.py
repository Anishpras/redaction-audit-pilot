#!/usr/bin/env python3
"""Regenerate cases.jsonl (explicit matched pairs) from the pilot's data/ files.

    python3 examples/consent-share/export_from_pilot.py
"""
import json
from collections import OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE.parent.parent / "data"

fixtures = json.loads((DATA / "fixtures.json").read_text(), object_pairs_hook=OrderedDict)
manifest = json.loads((DATA / "manifest.json").read_text(), object_pairs_hook=OrderedDict)
records = {r["case_id"]: r for r in fixtures["records"]}
lines = []
for c in manifest["cases"]:  # manifest order: pair by pair
    lines.append(json.dumps(OrderedDict([
        ("case_id", c["case_id"]), ("pair_id", c["pair_id"]), ("family", c["family"]),
        ("label", c["expected_verdict"]), ("log", {"events": records[c["case_id"]]["events"]}),
    ])))
(HERE / "cases.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("wrote %d cases to %s" % (len(lines), HERE / "cases.jsonl"))
