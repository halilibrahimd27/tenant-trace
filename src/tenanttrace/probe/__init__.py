"""Dynamic engine — language-agnostic, speaks only HTTP.

Boots a target with two seeded tenants and tries to reach tenant B's data while
authenticated as tenant A. Findings from this engine are `confirmed`: the oracle
decides on seeded ground truth, not on similarity heuristics.

This is the product. See ADR-0002.
"""
