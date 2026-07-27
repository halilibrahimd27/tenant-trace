"""The leak oracle: decides whether a response contains another tenant's data.

This module is why TenantTrace's findings are facts rather than scores. We
seeded the data, so we know exactly what tenant B's records say and how many
rows tenant A owns. A decision is a lookup against ground truth, never a
similarity judgement (ADR-0003).

Three signals, in order of strength:

1. **Canary strings.** Every seeded record carries ``tt-canary-<label>-<hex>``
   in a human-text field. Finding the victim's canary in a response served to
   the actor is conclusive, and it works on any body format — JSON, HTML, CSV,
   a PDF export — because it is a string search, not a schema comparison.
2. **Object identifiers.** The victim's record ids are secondary evidence.
   They are weaker than canaries for one specific reason handled below: the
   attack usually *sends* an id, and an application that echoes it back in an
   error message would otherwise look like a leak.
3. **Counts.** We seeded the actor's rows, so we know the correct aggregate.
   Anything higher includes somebody else's data.

When none of these can decide — a transport error, a 5xx, a body we cannot
read — the verdict is ``INCONCLUSIVE``. That is an honest answer and it is
never silently upgraded to "enforced".
"""

from __future__ import annotations

import enum
import json
import re
import secrets
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from tenanttrace.core.models import (
    CANARY_PREFIX,
    CANARY_RE,
    THROTTLE_STATUSES,
    TenantContext,
    TenantLabel,
    Verdict,
)

__all__ = [
    "AccessMode",
    "CANARY_RE",
    "MAX_SCAN_BYTES",
    "MIN_TRUSTWORTHY_ID_LENGTH",
    "OracleDecision",
    "ResponseFacts",
    "TenantOracle",
    "iter_json_scalars",
    "iter_json_strings",
    "make_canary",
    "scan_for_identifiers",
    "scan_for_markers",
]

# A canary is a fixed prefix, a tenant label, and enough entropy that a
# collision with real application data is not a thing that happens. The format
# itself lives in core.models — the renderers need it too.
#
# Bodies larger than this are scanned only up to the limit. A leak that only
# appears beyond 4 MiB of response is a case we would rather under-report than
# turn the prober into a memory hazard; the truncation is recorded in the
# decision reason so it is never invisible.
MAX_SCAN_BYTES = 4 * 1024 * 1024


def make_canary(label: TenantLabel | str) -> str:
    """Mint a canary for a tenant.

    ``secrets`` rather than ``random``: a predictable canary in a shared
    environment would let an application special-case it.
    """
    text = label.value if isinstance(label, TenantLabel) else str(label)
    return f"{CANARY_PREFIX}-{text}-{secrets.token_hex(8)}"


class AccessMode(enum.StrEnum):
    """What kind of access was attempted, which decides how silence is read.

    The distinction matters. A collection endpoint that returns 200 with none
    of the victim's rows has *enforced* isolation — that is the correct,
    expected response. A single-object endpoint that returns 200 for another
    tenant's id while showing none of that object's seeded content has done
    something we cannot explain, and pretending it is enforcement would hide a
    partial leak. So the first case is ENFORCED and the second INCONCLUSIVE.
    """

    OBJECT = "object"
    COLLECTION = "collection"
    AGGREGATE = "aggregate"
    WRITE = "write"


@dataclass(frozen=True, slots=True)
class ResponseFacts:
    """The bits of an HTTP response the oracle looks at.

    Kept transport-neutral so the oracle can be tested without httpx and so a
    future HAR replay mode can feed it recorded responses.
    """

    status: int | None
    text: str
    json_body: Any | None = None
    transport_error: str | None = None
    truncated: bool = False

    @property
    def failed(self) -> bool:
        """True when no usable response came back at all."""
        return self.transport_error is not None or self.status is None


@dataclass(frozen=True, slots=True)
class OracleDecision:
    """A verdict plus everything needed to prove it in a report."""

    verdict: Verdict
    reason: str
    matched_canary: str | None = None
    matched_ids: tuple[str, ...] = ()
    expected_count: int | None = None
    observed_count: int | None = None

    @property
    def leaked(self) -> bool:
        return self.verdict is Verdict.LEAKED


def iter_json_strings(node: Any, *, depth: int = 0, max_depth: int = 64) -> Iterator[str]:
    """Yield every string reachable in a decoded JSON document, keys included.

    Recursion is bounded: a hostile or merely pathological body must not be
    able to exhaust the stack of a tool that people run in CI. Keys are
    included because an application that uses record ids as object keys
    (``{"018f-…": {...}}``) leaks through them just as effectively.
    """
    if depth > max_depth:
        return
    if isinstance(node, str):
        yield node
    elif isinstance(node, Mapping):
        for key, value in node.items():
            if isinstance(key, str):
                yield key
            yield from iter_json_strings(value, depth=depth + 1, max_depth=max_depth)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from iter_json_strings(item, depth=depth + 1, max_depth=max_depth)


# An identifier shorter than this cannot be judged from a response body.
#
# The reason is arithmetic, not taste. With auto-increment primary keys — the
# default in Rails, Django, and Laravel — the victim's ids are "4", "5", "6",
# and those digits appear inside the actor's OWN data: in `"amount": 104`, in a
# timestamp, in a tenant slug, in the hex of the actor's own canary. Searching
# for them found a "leak" in 200 out of 200 correctly-isolated responses.
#
# So short ids are collected as corroboration and never as proof. A real leak
# in such an application is still caught by the canary, which is what the
# oracle leads with anyway (ADR-0003).
MIN_TRUSTWORTHY_ID_LENGTH = 8

# Numbers need far more digits than that, because a number shares a namespace
# with every other number in a response body.
MIN_TRUSTWORTHY_NUMERIC_ID_LENGTH = 12


def iter_json_scalars(node: Any, *, depth: int = 0, max_depth: int = 64) -> Iterator[str]:
    """Yield every scalar in a decoded document, rendered as a string.

    Keys are included: some APIs key a collection by id
    (``{"018f-…": {...}}``), and a leak through those is still a leak.
    Booleans are skipped — ``True`` is an ``int`` in Python, and no identifier
    is a boolean.
    """
    if depth > max_depth:
        return
    if isinstance(node, Mapping):
        for key, value in node.items():
            if isinstance(key, str):
                yield key
            yield from iter_json_scalars(value, depth=depth + 1, max_depth=max_depth)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from iter_json_scalars(item, depth=depth + 1, max_depth=max_depth)
    elif isinstance(node, bool):
        return
    elif isinstance(node, (str, int, float)):
        yield str(node)


def _normalise_key(key: str) -> str:
    """``tenantId``, ``tenant_id`` and ``TENANT-ID`` are the same field."""
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _iter_pairs(node: Any, *, depth: int = 0, max_depth: int = 64) -> Iterator[tuple[str, Any]]:
    """Yield every ``(key, scalar value)`` pair in a decoded document."""
    if depth > max_depth:
        return
    if isinstance(node, Mapping):
        for key, value in node.items():
            if isinstance(key, str) and not isinstance(value, (Mapping, list, tuple)):
                yield key, value
            yield from _iter_pairs(value, depth=depth + 1, max_depth=max_depth)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _iter_pairs(item, depth=depth + 1, max_depth=max_depth)


def _bounded_in_text(needle: str, haystack: str) -> bool:
    """True when ``needle`` appears in ``haystack`` delimited by non-id characters.

    Used only for bodies we could not parse. ``"4" in text`` is meaningless;
    ``018f4c1e-…`` bounded by quotes or whitespace is not.
    """
    for match in re.finditer(re.escape(needle), haystack):
        before = haystack[match.start() - 1] if match.start() else ""
        after = haystack[match.end()] if match.end() < len(haystack) else ""
        if not (before.isalnum() or before in "-_") and not (after.isalnum() or after in "-_"):
            return True
    return False


def is_judgeable_identifier(identifier: str) -> bool:
    """Whether an id carries enough entropy to be evidence on its own.

    Two thresholds, because two things collide differently. A UUID or a hash
    is unique enough that seeing it anywhere is meaningful. A *number* shares a
    namespace with every other number in the document — amounts, counts,
    timestamps, page sizes — so it needs to be long before it means anything,
    and a freshly-seeded auto-increment id never will be.
    """
    if not identifier:
        return False
    if identifier.isdigit():
        return len(identifier) >= MIN_TRUSTWORTHY_NUMERIC_ID_LENGTH
    return len(identifier) >= MIN_TRUSTWORTHY_ID_LENGTH


def scan_for_identifiers(facts: ResponseFacts, identifiers: Iterable[str]) -> tuple[str, ...]:
    """Victim identifiers present in the response, matched exactly.

    Deliberately stricter than :func:`scan_for_markers`. A canary is a long
    unique string we minted, so a substring hit is conclusive. An id is
    somebody else's value in somebody else's format, so it is matched by exact
    equality against the document's scalars — or, for a body we could not
    parse, as a boundary-delimited token. ``"4" in text`` is not evidence of
    anything.
    """
    wanted = [i for i in identifiers if is_judgeable_identifier(i)]
    if not wanted:
        return ()

    scalars = set(iter_json_scalars(facts.json_body)) if facts.json_body is not None else set()

    found: list[str] = []
    for identifier in wanted:
        if identifier in scalars:
            found.append(identifier)
        elif not identifier.isdigit() and _bounded_in_text(identifier, facts.text):
            # A long non-numeric id embedded in prose — {"note": "see 018f…"} —
            # is still a leak, and at this length it cannot collide with
            # anything. Numeric ids get no text search at all: digits embed in
            # every amount and timestamp in the document.
            found.append(identifier)
    return tuple(sorted(found))


def scan_for_markers(facts: ResponseFacts, markers: Iterable[str]) -> tuple[str, ...]:
    """Return the markers present in a response, in the order given.

    Two passes on purpose. The raw-text pass is format-agnostic and catches a
    canary in HTML, CSV, or a template-rendered page. The JSON pass catches the
    case where the transport applied an encoding — a canary inside a
    base64-free but escape-heavy JSON string still shows up decoded — and it is
    what lets a caller reason about ids that appear as object keys.

    Empty markers are ignored rather than matched: an empty needle is in every
    haystack, and that would report a leak on every single response.
    """
    wanted = [m for m in markers if m]
    if not wanted:
        return ()

    haystacks = [facts.text]
    if facts.json_body is not None:
        haystacks.extend(iter_json_strings(facts.json_body))

    found: list[str] = []
    for marker in wanted:
        if any(marker in hay for hay in haystacks):
            found.append(marker)
    return tuple(found)


@dataclass
class TenantOracle:
    """Judges responses served to ``actor`` for traces of ``victim``.

    One oracle per attacking direction. A→B and B→A are separate oracles, and
    running both is what proves the isolation is symmetric rather than an
    accident of ordering.
    """

    actor: TenantContext
    victim: TenantContext
    tenant_columns: tuple[str, ...] = ("tenant_id",)
    _victim_ids: frozenset[str] = field(init=False, repr=False)
    _actor_ids: frozenset[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._victim_ids = frozenset(self.victim.record_ids())
        self._actor_ids = frozenset(self.actor.record_ids())

    # ------------------------------------------------------------------ #
    def owner_fields(self, facts: ResponseFacts, tenant: TenantContext) -> tuple[str, ...]:
        """Ownership fields in the response that name ``tenant`` as the owner.

        The third evidence signal, and the one that works where the other two
        cannot. A canary needs a text field the caller can write and read back;
        an identifier needs entropy. Plenty of real applications offer neither —
        no user-writable free text anywhere, and ``Long`` auto-increment primary
        keys — and until this existed those applications could not be audited at
        all.

        This is precise where bare id matching was not, because it compares the
        value stored *under a named ownership key* rather than scanning the body
        for a number. ``{"userId": 2}`` in a response served to user 3 is
        conclusive; ``{"amount": 2}`` is not even looked at.
        """
        if facts.json_body is None or not tenant.tenant_id:
            return ()
        wanted = {_normalise_key(column) for column in self.tenant_columns}
        found: list[str] = []
        for key, value in _iter_pairs(facts.json_body):
            if _normalise_key(key) in wanted and str(value) == tenant.tenant_id:
                found.append(f"{key}={value}")
        return tuple(dict.fromkeys(found))

    # ------------------------------------------------------------------ #
    # Evidence gathering
    # ------------------------------------------------------------------ #
    def victim_markers(self) -> tuple[str, ...]:
        """Canaries belonging to the victim: the strongest possible evidence."""
        canaries = {self.victim.canary}
        canaries.update(record.canary for record in self.victim.records if record.canary)
        return tuple(sorted(canaries))

    def leaked_ids(self, facts: ResponseFacts, *, sent_ids: Iterable[str] = ()) -> tuple[str, ...]:
        """Victim record ids the response presents as identifiers, minus ours.

        Two exclusions, both load-bearing.

        **Ids we sent** are dropped, because an IDOR attempt puts the victim's
        id in the request URL and plenty of well-behaved applications echo it
        back: ``{"detail": "Invoice 018f-… not found"}``. Counting that would
        report a critical against an application that did the right thing.

        **Ids too short to be evidence** are dropped by
        :func:`scan_for_identifiers` — see :data:`MIN_TRUSTWORTHY_ID_LENGTH`.
        """
        echoed = {str(i) for i in sent_ids}
        candidates = [i for i in sorted(self._victim_ids) if i not in echoed]
        return scan_for_identifiers(facts, candidates)

    def unjudgeable_ids(self) -> tuple[str, ...]:
        """Victim ids too short or too numeric to be used as evidence.

        Surfaced rather than silently discarded: an operator whose application
        uses integer primary keys should know that this run leaned entirely on
        canaries, instead of assuming id coverage they did not get.
        """
        return tuple(sorted(i for i in self._victim_ids if not is_judgeable_identifier(i)))

    # ------------------------------------------------------------------ #
    # Verdicts
    # ------------------------------------------------------------------ #
    def judge(
        self,
        facts: ResponseFacts,
        *,
        mode: AccessMode,
        sent_ids: Iterable[str] = (),
        speculative_path: bool = False,
    ) -> OracleDecision:
        """Decide whether this response leaked the victim's data.

        Ordering is deliberate: positive evidence is checked before any
        status-code reasoning, because a leak inside a 500 is still a leak, and
        an application that returns 200 with an empty body has not proven
        anything either way.
        """
        canaries = scan_for_markers(facts, self.victim_markers())
        if canaries:
            return OracleDecision(
                verdict=Verdict.LEAKED,
                reason=(
                    f"response served to tenant {self.actor.label} contains tenant "
                    f"{self.victim.label}'s seeded canary"
                ),
                matched_canary=canaries[0],
                matched_ids=self.leaked_ids(facts, sent_ids=sent_ids),
            )

        owned = self.owner_fields(facts, self.victim)
        if owned:
            return OracleDecision(
                verdict=Verdict.LEAKED,
                reason=(
                    f"response served to tenant {self.actor.label} carries "
                    f"{', '.join(owned[:3])}, naming tenant {self.victim.label} as the owner"
                ),
                matched_ids=owned,
            )

        ids = self.leaked_ids(facts, sent_ids=sent_ids)
        if ids:
            return OracleDecision(
                verdict=Verdict.LEAKED,
                reason=(
                    f"response contains {len(ids)} identifier(s) belonging to tenant "
                    f"{self.victim.label} that were not part of the request"
                ),
                matched_ids=ids,
            )

        if facts.transport_error is not None:
            return OracleDecision(
                verdict=Verdict.INCONCLUSIVE,
                reason=f"no response to judge: {facts.transport_error}",
            )

        status = facts.status
        if status is None:
            return OracleDecision(Verdict.INCONCLUSIVE, "no status code on the response")
        if status >= 500:
            return OracleDecision(
                verdict=Verdict.INCONCLUSIVE,
                reason=(
                    f"target returned {status}; a server error is not evidence of "
                    "enforcement, and the endpoint should be re-checked"
                ),
            )

        return self._judge_quiet_response(
            facts, mode=mode, status=status, speculative_path=speculative_path
        )

    def _judge_quiet_response(
        self,
        facts: ResponseFacts,
        *,
        mode: AccessMode,
        status: int,
        speculative_path: bool = False,
    ) -> OracleDecision:
        """Read a response that carried no victim data at all."""
        truncated = " (body truncated before scanning)" if facts.truncated else ""

        # A body we only partly read cannot support "nothing of the victim's is
        # in here" — the part we skipped is exactly where it might be. Silence
        # from a truncated scan is an unknown, not enforcement.
        if facts.truncated:
            return OracleDecision(
                verdict=Verdict.INCONCLUSIVE,
                reason=(
                    f"response exceeded the {MAX_SCAN_BYTES // (1024 * 1024)} MiB scan limit, "
                    "so the unscanned remainder could contain the other tenant's data; this "
                    "is not evidence of isolation"
                ),
            )

        # 429 is the server declining to *process* the request. It is not a
        # decision about who owns the object, and counting it as one means a
        # target that rate-limits the prober into uselessness reports as
        # "refused everything, correctly" — the exact failure RunStatus.INVALID
        # exists to prevent, arriving through a door rule 4 did not cover.
        # Found by auditing a real application that answered 429 to 134 of 168
        # attempts and was reported clean.
        if status in THROTTLE_STATUSES:
            return OracleDecision(
                verdict=Verdict.INCONCLUSIVE,
                reason=(
                    f"target answered {status}: the request was throttled, so the "
                    "application never decided whether this tenant may have the object"
                ),
            )

        # A redirect is not a refusal. `Location: /login` might be, but so might
        # `303 -> /api/invoices/<id>`, which is the object being served one hop
        # later. Counting every 3xx as "correctly refused" inflated coverage
        # with attempts that were never actually resolved.
        if 300 <= status < 400:
            return OracleDecision(
                verdict=Verdict.INCONCLUSIVE,
                reason=(
                    f"target answered {status} with a redirect, which was not followed "
                    "(a redirect can leave allowed_hosts). Whether the destination "
                    "serves the object is unknown."
                ),
            )

        if mode is AccessMode.OBJECT:
            # A 404 for a path we assembled by putting one id into several
            # parameter slots is far more likely to mean "no such URL" than
            # "you may not have this". 401/403 are still real authorisation
            # decisions and stay ENFORCED — only 404 is ambiguous here.
            if status == 404 and speculative_path:
                return OracleDecision(
                    verdict=Verdict.INCONCLUSIVE,
                    reason=(
                        "target returned 404, but the request path carried the same "
                        "identifier in every parameter, so the URL probably addressed "
                        "no record at all; this is not evidence of enforcement"
                    ),
                )
            if status in {401, 403, 404}:
                return OracleDecision(
                    verdict=Verdict.ENFORCED,
                    reason=f"target refused the cross-tenant object with {status}",
                )
            if 200 <= status < 300:
                # Access was granted to another tenant's identifier but the body
                # shows none of its seeded content. That is not enforcement and
                # it is not a proven leak — it needs a human.
                return OracleDecision(
                    verdict=Verdict.INCONCLUSIVE,
                    reason=(
                        f"target returned {status} for another tenant's object id but the "
                        f"body contains none of its seeded content{truncated}; check "
                        "whether the endpoint serves a partial or redacted view"
                    ),
                )
            return OracleDecision(
                verdict=Verdict.ENFORCED,
                reason=f"target rejected the request with {status}",
            )

        if mode is AccessMode.COLLECTION:
            if 200 <= status < 300:
                return OracleDecision(
                    verdict=Verdict.ENFORCED,
                    reason=f"collection returned {status} with no rows from the other tenant",
                )
            if status in {401, 403, 404}:
                return OracleDecision(
                    verdict=Verdict.ENFORCED,
                    reason=f"target refused the collection with {status}",
                )
            return OracleDecision(
                verdict=Verdict.INCONCLUSIVE,
                reason=f"unexpected status {status} on a collection endpoint{truncated}",
            )

        if mode is AccessMode.WRITE:
            if 200 <= status < 300:
                return OracleDecision(
                    verdict=Verdict.INCONCLUSIVE,
                    reason=(
                        f"write accepted with {status}; ownership of the created record "
                        "still has to be confirmed by reading it back"
                    ),
                )
            return OracleDecision(
                verdict=Verdict.ENFORCED,
                reason=f"target rejected the cross-tenant write with {status}",
            )

        return OracleDecision(
            verdict=Verdict.INCONCLUSIVE,
            reason=f"no count to compare against on a {status} response{truncated}",
        )

    # ------------------------------------------------------------------ #
    # Aggregates
    # ------------------------------------------------------------------ #
    def judge_count(
        self,
        facts: ResponseFacts,
        *,
        field_name: str,
        expected: int,
    ) -> OracleDecision:
        """Compare one numeric field against what the actor actually owns.

        Assumption, and how it can be wrong: the actor's tenant was created by
        this run, so the only rows it owns are the ones we seeded. Point the
        prober at a tenant that already had data and ``expected`` is too low,
        which would report a leak that is not there. The runner therefore
        refuses to treat a count as evidence unless the tenant was seeded in
        this run.
        """
        if facts.failed:
            return OracleDecision(
                verdict=Verdict.INCONCLUSIVE,
                reason=f"aggregate unavailable: {facts.transport_error or 'no response'}",
                expected_count=expected,
            )
        if facts.status is not None and facts.status >= 400:
            return OracleDecision(
                verdict=Verdict.ENFORCED,
                reason=f"aggregate endpoint returned {facts.status}",
                expected_count=expected,
            )

        observed = _extract_number(facts.json_body, field_name)
        if observed is None:
            return OracleDecision(
                verdict=Verdict.INCONCLUSIVE,
                reason=f"could not read a numeric {field_name!r} from the aggregate response",
                expected_count=expected,
            )

        if observed > expected:
            return OracleDecision(
                verdict=Verdict.LEAKED,
                reason=(
                    f"{field_name} is {observed} for tenant {self.actor.label}, which owns "
                    f"{expected} — the aggregate is computed over other tenants' rows"
                ),
                expected_count=expected,
                observed_count=observed,
            )
        return OracleDecision(
            verdict=Verdict.ENFORCED,
            reason=f"{field_name} is {observed}, consistent with the {expected} row(s) owned",
            expected_count=expected,
            observed_count=observed,
        )

    def judge_ownership(
        self,
        facts: ResponseFacts,
        *,
        tenant_field: str,
    ) -> OracleDecision:
        """Decide whether a record we just created landed in the victim tenant.

        Used by the mass-assignment attack, where the proof is not that data
        came back but that data went somewhere it should not have.
        """
        if facts.failed:
            return OracleDecision(
                verdict=Verdict.INCONCLUSIVE,
                reason="could not read the created record back to check its owner",
            )
        if facts.status is not None and facts.status >= 400:
            # The write was refused. Checking the body for an owner field would
            # only turn a clear rejection into an inconclusive result, which is
            # noise: a 422 on a payload carrying somebody else's tenant id is
            # exactly the behaviour we are testing for.
            return OracleDecision(
                verdict=Verdict.ENFORCED,
                reason=f"target rejected the cross-tenant write with {facts.status}",
            )
        if facts.json_body is None:
            return OracleDecision(
                verdict=Verdict.INCONCLUSIVE,
                reason="created record was not returned in a form we can check for ownership",
            )
        owner = _extract_string(facts.json_body, tenant_field)
        if owner is None:
            return OracleDecision(
                verdict=Verdict.INCONCLUSIVE,
                reason=f"created record does not expose a {tenant_field!r} field to check",
            )
        if owner == self.victim.tenant_id:
            return OracleDecision(
                verdict=Verdict.LEAKED,
                reason=(
                    f"record created by tenant {self.actor.label} is owned by tenant "
                    f"{self.victim.label} ({tenant_field}={owner})"
                ),
                matched_ids=(owner,),
            )
        return OracleDecision(
            verdict=Verdict.ENFORCED,
            reason=f"created record stayed with the caller ({tenant_field}={owner})",
        )


def _walk_values(node: Any, key: str, *, depth: int = 0) -> Iterator[Any]:
    """Yield every value stored under ``key`` anywhere in a JSON document."""
    if depth > 32:
        return
    if isinstance(node, Mapping):
        for k, v in node.items():
            if k == key:
                yield v
            yield from _walk_values(v, key, depth=depth + 1)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _walk_values(item, key, depth=depth + 1)


def _as_count(value: Any) -> int | None:
    """Coerce a JSON value to a row count, or None if it is not one.

    Booleans are rejected: in Python ``True`` is an ``int``, and an aggregate
    field that is actually a flag must not be compared against a row count.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _extract_number(body: Any, key: str) -> int | None:
    """The numeric value stored under ``key``, preferring the top level.

    Top level first, and it matters: the caller picked this field by reading
    the top-level object, so a nested field that happens to share the name —
    ``{"invoice_count": 3, "archived": {"invoice_count": 900}}`` — must not
    shadow the number that was actually chosen. Walking the whole document and
    taking the first hit compared the wrong figure against the seeded count.
    """
    if isinstance(body, Mapping) and key in body:
        top = _as_count(body[key])
        if top is not None:
            return top
    for value in _walk_values(body, key):
        count = _as_count(value)
        if count is not None:
            return count
    return None


def _extract_string(body: Any, key: str) -> str | None:
    """First string value stored under ``key``, or None."""
    for value in _walk_values(body, key):
        if isinstance(value, str):
            return value
    return None


def facts_from_parts(
    *,
    status: int | None,
    text: str,
    transport_error: str | None = None,
) -> ResponseFacts:
    """Build :class:`ResponseFacts`, decoding JSON when the body permits it.

    A body that does not parse as JSON is not an error — the canary scan works
    on raw text by design, which is what makes the oracle format-agnostic.
    """
    truncated = False
    if len(text) > MAX_SCAN_BYTES:
        text = text[:MAX_SCAN_BYTES]
        truncated = True

    parsed: Any | None = None
    stripped = text.lstrip()
    if stripped[:1] in {"{", "["}:
        try:
            parsed = json.loads(text)
        except (ValueError, RecursionError):
            parsed = None

    return ResponseFacts(
        status=status,
        text=text,
        json_body=parsed,
        transport_error=transport_error,
        truncated=truncated,
    )


def expected_counts(actor: TenantContext, kinds: Sequence[str]) -> dict[str, int]:
    """How many records of each kind the actor owns, from the seeding record."""
    return {kind: actor.count_of(kind) for kind in kinds}
