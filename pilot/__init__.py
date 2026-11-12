"""Redaction audit pilot: what evidence do agent audit logs need after redaction?

Modules
-------
fixtures  hand-specified synthetic records and the separate expected-label manifest
policy    trusted-fact oracle used only to check the hand-written labels
views     A (full), B (uniform masking), C (consistent aliases) and two C ablations
reviewer  standalone deterministic reviewer (stdin -> stdout, standard library only)
exposure  planted-value scanner for direct exposure
scoring   metrics 1-4
validate  pre-run and post-run checks
"""
