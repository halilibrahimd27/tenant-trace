"""Check whether counts and totals are computed over other tenants' rows.

An aggregate leak discloses no row content, so it is rated below a direct read
— but it is worth reporting on its own terms. A dashboard that tells tenant A
how many invoices exist in the whole system is a disclosure, and in practice it
is the same forgotten predicate that will leak rows on the next endpoint
somebody adds.

The oracle here is arithmetic rather than string matching: we seeded the
actor's rows, so we know the correct answer.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from typing import Any

from tenanttrace.core.models import AttackName, ProbeResult, Verdict
from tenanttrace.probe.attacks.base import AttackContext
from tenanttrace.probe.oracle import ResponseFacts

__all__ = ["AggregateAttack"]

# Field names that count ROWS of some resource: `invoice_count`,
# `invoices_count`, `count_documents`.
#
# `total` is deliberately excluded, and it is worth explaining why, because
# including it is the obvious thing to do and it is wrong. `invoice_total`
# almost always means a sum of money, not a number of invoices — comparing
# 303.00 against "this tenant owns 3 rows" reports a critical leak in an
# application that is behaving perfectly. Sums cannot be judged without knowing
# what is being summed, and this tool does not guess.
#
# The coverage cost is small in practice: an endpoint that sums across tenants
# is almost always the same endpoint that counts across tenants, and the count
# field catches it. Where it is not, that gap is documented in the README
# rather than papered over with a heuristic that fires on correct code.
_COUNT_SUFFIX_RE = re.compile(r"^(?P<name>[a-z0-9_]+?)_count$")
_COUNT_PREFIX_RE = re.compile(r"^count_(?P<name>[a-z0-9_]+)$")


def _singular(word: str) -> str:
    if word.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def _countable_fields(body: Any) -> dict[str, str]:
    """Map ``field name -> record kind`` for fields that look like row counts.

    Assumption, and how it can be wrong: a field called ``<thing>_count`` counts
    rows of ``<thing>``. A field that counts something else entirely — API
    calls, seats, days — would be compared against the wrong number. That is
    why a mismatch is only reported when the resource name matches a kind we
    actually seeded; an unknown name is skipped rather than guessed at.
    """
    if not isinstance(body, Mapping):
        return {}
    mapping: dict[str, str] = {}
    for raw_key, value in body.items():
        key = str(raw_key).lower()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        match = _COUNT_SUFFIX_RE.match(key) or _COUNT_PREFIX_RE.match(key)
        if not match:
            continue
        name = match.groupdict().get("name") or ""
        if name:
            mapping[str(raw_key)] = _singular(name)
    return mapping


class AggregateAttack:
    """Compare every count-shaped field against what the actor actually owns."""

    name = AttackName.AGGREGATE

    def run(self, ctx: AttackContext) -> Iterator[ProbeResult]:
        seeded_kinds = {record.kind for record in ctx.actor_ctx.records}

        for endpoint in ctx.inventory.collections():
            if ctx.is_allowlisted(endpoint):
                continue

            exchange = ctx.actor.request(endpoint.method, endpoint.path, attack=self.name.value)
            facts: ResponseFacts = exchange.facts()
            fields = _countable_fields(facts.json_body)
            if not fields:
                continue

            for field_name, kind in fields.items():
                if kind not in seeded_kinds:
                    # We have no ground truth for this resource, so any
                    # comparison would be a guess. Skipping silently is correct
                    # here: this is not an untested endpoint, it is a field we
                    # deliberately decline to judge.
                    continue

                expected = ctx.actor_ctx.count_of(kind)
                decision = ctx.oracle.judge_count(facts, field_name=field_name, expected=expected)
                if decision.verdict is Verdict.ENFORCED and not decision.observed_count:
                    continue

                evidence = exchange.evidence().model_copy(
                    update={
                        "expected_count": decision.expected_count,
                        "observed_count": decision.observed_count,
                        "note": f"field {field_name!r} counts {kind} rows",
                    }
                )
                yield ProbeResult(
                    attack=self.name,
                    endpoint=endpoint,
                    actor=ctx.actor_ctx.label,
                    target=ctx.victim_ctx.label,
                    verdict=decision.verdict,
                    evidence=evidence,
                    detail=decision.reason,
                )
