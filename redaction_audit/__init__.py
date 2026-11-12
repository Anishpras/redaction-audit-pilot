"""redaction_audit: test whether a redacted action log still lets a reviewer verify a policy.

You describe four things as files:
  policy.json   the authorisation rule as conditions, each with an *evidence need*
                (equality, order, explicit_state, raw_value, presence)
  fields.json   which log fields are private (identifier / name / content) and which are times
  views.json    the redaction transforms to test (built-in ops or your own command)
  cases.jsonl   authorised example logs (unauthorised partners are generated), or
                explicitly labelled matched pairs

and get, for every condition and transform, whether the condition stays
*verified*, becomes *unverifiable*, or becomes *unsafe* (the reviewer is misled
into a wrong verdict), plus the direct exposure of private values.

Standard library only. See docs/tutorial.md.
"""
__version__ = "1.2.0"
