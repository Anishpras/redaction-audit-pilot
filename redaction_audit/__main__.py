"""Command line: python3 -m redaction_audit {run,init,checklist} ...

  run        audit redaction views against a policy (exit 1 if --fail-on statuses occur in --gate views)
  init DIR   copy a commented starter audit (policy, fields, views, cases) into DIR
  checklist  print the evidence requirements implied by a policy, without running anything
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from . import __version__, run as run_mod, spec

TEMPLATE = Path(__file__).resolve().parent / "template"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="redaction-audit", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="redaction_audit " + __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run an audit")
    r.add_argument("--policy", required=True)
    r.add_argument("--fields", required=True)
    r.add_argument("--cases", required=True)
    r.add_argument("--views", required=True)
    r.add_argument("--out", default="audit-out")
    r.add_argument("--reviewer", default="builtin",
                   help="builtin (reads redaction declarations), undeclared (ignores them), "
                        "or exec:<command> (your reviewer: stdin {policy, log}, stdout {verdict, checks?})")
    r.add_argument("--reviewer-env", action="append", default=[],
                   help="environment variable to pass to an exec reviewer (repeatable)")
    r.add_argument("--fail-on", default="",
                   help="comma list: unsafe, unverifiable, unsafe-undeclared (wrong verdicts if the redaction "
                        "header is lost), exposed (any private value visible)")
    r.add_argument("--gate", action="append", default=None,
                   help="view(s) the --fail-on check applies to (repeatable or comma-separated; default: all)")
    r.add_argument("--seed", type=int, default=20261113, help="seed for the reviewer call order")

    i = sub.add_parser("init", help="write a starter audit into a directory")
    i.add_argument("dir")

    c = sub.add_parser("checklist", help="print the evidence requirements for a policy")
    c.add_argument("--policy", required=True)

    args = ap.parse_args(argv)
    try:
        if args.cmd == "run":
            fail_on = tuple(s.strip() for s in args.fail_on.split(",") if s.strip())
            allowed = ("unsafe", "unverifiable", "unsafe-undeclared", "exposed")
            bad = [s for s in fail_on if s not in allowed]
            if bad:
                raise spec.SpecError("--fail-on accepts %s, not %s%s" % (", ".join(allowed), bad, spec.hint(bad[0], allowed)))
            gate = [g.strip() for item in (args.gate or []) for g in item.split(",") if g.strip()] or None
            return run_mod.run(args.policy, args.fields, args.cases, args.views, args.out,
                               reviewer=args.reviewer, seed=args.seed, env_keep=args.reviewer_env,
                               fail_on=fail_on, gate=gate)
        if args.cmd == "init":
            dest = Path(args.dir)
            if dest.exists() and any(dest.iterdir()):
                raise spec.SpecError("%s exists and is not empty" % dest)
            shutil.copytree(TEMPLATE, dest, dirs_exist_ok=True)
            print("Wrote a starter audit to %s. Next:\n  python3 -m redaction_audit run --policy %s/policy.json "
                  "--fields %s/fields.json --cases %s/cases.jsonl --views %s/views.json --out %s/out"
                  % (dest, dest, dest, dest, dest, dest))
            return 0
        if args.cmd == "checklist":
            policy = spec.check_policy(spec.load_json(args.policy))
            sys.stdout.write(run_mod.evidence_requirements_md(policy))
            return 0
    except spec.SpecError as exc:
        print("error:", file=sys.stderr)
        for p in exc.problems:
            print("  - " + p, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
