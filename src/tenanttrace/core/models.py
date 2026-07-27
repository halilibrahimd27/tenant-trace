"""The vocabulary the whole project speaks.

Everything crossing a module boundary is one of these types. Engines produce
them, the correlator merges them, the renderers consume them — so a change here
is a change to the contract, not an implementation detail.

Design notes:

* Enums are ``StrEnum`` so they serialise to plain strings in JSON and stay
  readable in a report without a custom encoder.
* Value objects are frozen. A :class:`Finding` that came out of an engine must
  never be edited in place by a later stage; the correlator builds new ones.
* Ordering lives in explicit ``rank`` properties rather than enum member order,
  because "critical is worse than high" is a fact about severity, not about the
  order somebody happened to type the members in.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "THROTTLE_STATUSES",
    "ATTACK_CATEGORIES",
    "CANARY_PREFIX",
    "CANARY_RE",
    "AttackName",
    "Category",
    "Confidence",
    "ControlResult",
    "Endpoint",
    "Engine",
    "Evidence",
    "Finding",
    "HttpMethod",
    "ProbeResult",
    "RunReport",
    "RunStatus",
    "ScopingMode",
    "SeededRecord",
    "TenantContext",
    "TenantLabel",
    "Verdict",
    "utcnow",
]


def utcnow() -> datetime:
    """Timezone-aware now, in UTC. Naive datetimes are a bug in a report."""
    return datetime.now(UTC)


# The canary format is shared vocabulary: the prober mints these, the oracle
# searches for them, and the renderers shorten them. It lives here so that
# `core` never has to import from `probe` — the dependency arrow points inward.
CANARY_PREFIX = "tt-canary"
CANARY_RE = re.compile(rf"{CANARY_PREFIX}-[A-Za-z0-9]+-[0-9a-f]{{8,}}")


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


# Statuses that mean "not now", never "not yours". An application under a rate
# limiter has not authorised or refused anything, so a throttled attempt is not
# evidence of isolation in either direction.
THROTTLE_STATUSES: frozenset[int] = frozenset({429})


class Severity(enum.StrEnum):
    """How bad the finding is, independent of how sure we are about it."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher is worse. Used for sorting and for the CI ``fail_on`` gate."""
        return _SEVERITY_RANK[self]

    def at_least(self, threshold: Severity) -> bool:
        """True when this severity meets or exceeds ``threshold``."""
        return self.rank >= threshold.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(enum.StrEnum):
    """How sure we are. Only ``CONFIRMED`` may fail a build by default.

    ``SUSPECTED`` is what the static engine emits: a hypothesis, never a
    verdict. ``INCONCLUSIVE`` is the honest answer when the oracle could not
    decide — it is deliberately not a synonym for "clean".
    """

    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    INCONCLUSIVE = "inconclusive"

    @property
    def rank(self) -> int:
        """Higher outranks. At equal severity, confirmed always sorts first."""
        return _CONFIDENCE_RANK[self]


_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.INCONCLUSIVE: 0,
    Confidence.SUSPECTED: 1,
    Confidence.CONFIRMED: 2,
}


class Engine(enum.StrEnum):
    """Which half of the tool produced the finding."""

    PROBE = "probe"
    STATIC = "static"
    CORRELATED = "correlated"


class RunStatus(enum.StrEnum):
    """Whether the run itself can be trusted.

    ``INVALID`` exists because a harness that 403s everything would otherwise
    report "no leaks found" — the single most dangerous output this tool could
    produce.
    """

    VALID = "valid"
    INVALID = "invalid"
    ERROR = "error"


class Verdict(enum.StrEnum):
    """The oracle's decision about one attempted cross-tenant access."""

    LEAKED = "leaked"
    ENFORCED = "enforced"
    INCONCLUSIVE = "inconclusive"


class Category(enum.StrEnum):
    """What kind of isolation failure this is.

    The category drives severity, the CWE/OWASP/ASVS tags, and which
    remediation template renders — see :mod:`tenanttrace.core.severity`.
    """

    # --- dynamic: proven over HTTP ---------------------------------------
    CROSS_TENANT_READ = "cross_tenant_read"
    CROSS_TENANT_WRITE = "cross_tenant_write"
    LISTING_LEAK = "listing_leak"
    AGGREGATE_LEAK = "aggregate_leak"
    PARAM_OVERRIDE = "param_override"
    CACHE_KEY_LEAK = "cache_key_leak"
    PUBLIC_ENDPOINT = "public_endpoint"
    # --- static: hypotheses ----------------------------------------------
    MISSING_TENANT_FILTER = "missing_tenant_filter"
    RAW_SQL_ESCAPE = "raw_sql_escape"
    SCOPE_BYPASS_FLAG = "scope_bypass_flag"
    UNSCOPED_MODEL = "unscoped_model"
    TENANTLESS_CACHE_KEY = "tenantless_cache_key"
    TENANTLESS_JOB_PAYLOAD = "tenantless_job_payload"
    # --- harness ----------------------------------------------------------
    HARNESS_ERROR = "harness_error"


class HttpMethod(enum.StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"

    @property
    def is_safe(self) -> bool:
        """True for methods that must not change server state."""
        return self in _SAFE_METHODS


_SAFE_METHODS = frozenset({HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS})


class AttackName(enum.StrEnum):
    """Attack modules, by the name used in ``[probe] attacks``."""

    IDOR = "idor"
    LISTING = "listing"
    AGGREGATE = "aggregate"
    PARAM_OVERRIDE = "param_override"
    MASS_ASSIGN = "mass_assign"
    CACHE = "cache"

    @property
    def is_mutating(self) -> bool:
        """True when the module writes to the target (needs --allow-mutation)."""
        return self is AttackName.MASS_ASSIGN


ATTACK_CATEGORIES: Mapping[AttackName, Category] = {
    AttackName.IDOR: Category.CROSS_TENANT_READ,
    AttackName.LISTING: Category.LISTING_LEAK,
    AttackName.AGGREGATE: Category.AGGREGATE_LEAK,
    AttackName.PARAM_OVERRIDE: Category.PARAM_OVERRIDE,
    AttackName.MASS_ASSIGN: Category.CROSS_TENANT_WRITE,
    AttackName.CACHE: Category.CACHE_KEY_LEAK,
}


class ScopingMode(enum.StrEnum):
    """How the application under analysis scopes queries to a tenant.

    The correct static rule is the *opposite* in each mode, so picking wrong
    makes the static engine useless. See :mod:`tenanttrace.static.scoping`.
    """

    MANUAL = "manual"
    GLOBAL = "global"
    UNKNOWN = "unknown"


class TenantLabel(enum.StrEnum):
    """The two synthetic tenants. A is the attacker, B is the victim."""

    A = "A"
    B = "B"

    @property
    def other(self) -> TenantLabel:
        return TenantLabel.B if self is TenantLabel.A else TenantLabel.A


# --------------------------------------------------------------------------- #
# Value objects
# --------------------------------------------------------------------------- #


class _Frozen(BaseModel):
    """Base for immutable value objects."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class Endpoint(_Frozen):
    """One operation on the target, normalised from whatever spec described it.

    ``path`` keeps its template form (``/api/invoices/{id}``) so that endpoints
    stay comparable across runs even as ids change.
    """

    method: HttpMethod
    path: str
    operation_id: str | None = None
    summary: str | None = None
    path_params: tuple[str, ...] = ()
    query_params: tuple[str, ...] = ()
    body_fields: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    @field_validator("path")
    @classmethod
    def _leading_slash(cls, value: str) -> str:
        if not value.startswith("/"):
            msg = f"endpoint path must start with '/': {value!r}"
            raise ValueError(msg)
        return value

    @property
    def key(self) -> str:
        """Stable human-readable identity: ``GET /api/invoices/{id}``."""
        return f"{self.method.value} {self.path}"

    @property
    def is_object_endpoint(self) -> bool:
        """True when the path addresses a single object by id.

        Assumption: an endpoint with at least one path parameter identifies an
        object. It can be wrong (``/api/reports/{period}``), which is why IDOR
        results still have to clear the oracle before becoming findings.
        """
        return bool(self.path_params)

    @property
    def is_collection_endpoint(self) -> bool:
        """True when the path looks like a collection (no path parameters)."""
        return self.method is HttpMethod.GET and not self.path_params

    def __str__(self) -> str:
        return self.key


class SeededRecord(_Frozen):
    """One object the seeder created, and the canary planted inside it."""

    kind: str
    id: str
    canary: str
    owner: TenantLabel
    fields: Mapping[str, Any] = Field(default_factory=dict)
    # Values for path parameters other than this record's own id. A nested
    # resource needs its parents to be addressable at all:
    # /api/database/rows/table/{table_id}/rows/{row_id} cannot be built from a
    # row id alone, and filling {table_id} with it produces a URL for nothing.
    path: Mapping[str, str] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=True, extra="forbid")


class TenantContext(_Frozen):
    """Everything the prober knows about one synthetic tenant.

    ``headers`` carries live credentials. It is excluded from serialisation so
    a token cannot reach an artifact, a log line, or a PR comment by accident.
    """

    label: TenantLabel
    tenant_id: str
    canary: str
    headers: Mapping[str, str] = Field(default_factory=dict, exclude=True, repr=False)
    records: tuple[SeededRecord, ...] = ()
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    def record_ids(self, kind: str | None = None) -> tuple[str, ...]:
        """Ids of this tenant's seeded records, optionally filtered by kind."""
        return tuple(r.id for r in self.records if kind is None or r.kind == kind)

    def count_of(self, kind: str) -> int:
        """How many records of ``kind`` this tenant owns. The aggregate oracle."""
        return sum(1 for r in self.records if r.kind == kind)


class Evidence(_Frozen):
    """What actually happened, in enough detail to paste into a pentest report.

    Populated by the prober for dynamic findings and by the static engine for
    source locations. Both shapes coexist; unused fields stay ``None``.
    """

    # --- dynamic ----------------------------------------------------------
    request_method: HttpMethod | None = None
    request_url: str | None = None
    request_headers: Mapping[str, str] = Field(default_factory=dict)
    request_body: str | None = None
    response_status: int | None = None
    response_snippet: str | None = None
    elapsed_ms: float | None = None
    # --- the oracle's proof ----------------------------------------------
    matched_canary: str | None = None
    matched_ids: tuple[str, ...] = ()
    expected_count: int | None = None
    observed_count: int | None = None
    # --- static ------------------------------------------------------------
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    assumption: str | None = None
    note: str | None = None

    @property
    def request_line(self) -> str | None:
        """``GET /api/invoices/018f…`` — the one-liner a report card shows."""
        if self.request_method is None or self.request_url is None:
            return None
        return f"{self.request_method.value} {self.request_url}"


class Finding(_Frozen):
    """A reported isolation failure. The unit of everything user-facing."""

    id: str
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    engine: Engine
    location: str
    tags: tuple[str, ...] = ()
    evidence: Evidence = Field(default_factory=Evidence)
    remediation: str = ""
    fingerprint: str = ""
    related: tuple[str, ...] = ()

    @property
    def sort_key(self) -> tuple[int, int, str]:
        """Rank order: severity, then confidence, then a stable tiebreak.

        Confirmed outranks suspected at equal severity — an operator should
        never scroll past a proven leak to reach a hypothesis.
        """
        return (-self.severity.rank, -self.confidence.rank, self.location)

    @property
    def gates_ci(self) -> bool:
        """Whether this finding may fail a build (rule 3: confirmed only)."""
        return self.confidence is Confidence.CONFIRMED


class ProbeResult(_Frozen):
    """The outcome of one attempted cross-tenant access.

    A result is not a finding: only ``LEAKED`` verdicts become findings, and
    ``ENFORCED`` results are kept because "we tried and it held" is the
    evidence that the run had real coverage.
    """

    attack: AttackName
    endpoint: Endpoint
    actor: TenantLabel
    target: TenantLabel
    verdict: Verdict
    evidence: Evidence = Field(default_factory=Evidence)
    detail: str = ""
    # Normally the attack decides the category. An attack that establishes a
    # differential can overrule itself: an endpoint that serves the same data
    # to nobody at all is a missing-authentication problem, not a tenant-
    # scoping one, and the two need different fixes (ADR-0008, ADR-0011).
    category: Category | None = None

    @property
    def leaked(self) -> bool:
        return self.verdict is Verdict.LEAKED

    def category_of(self) -> Category:
        """The category to report, honouring an attack's own correction."""
        return self.category or ATTACK_CATEGORIES[self.attack]


class ControlResult(_Frozen):
    """A positive control: proof the harness itself works.

    If A cannot read A's own data, nothing else in the run means anything.
    """

    name: str
    passed: bool
    detail: str = ""
    evidence: Evidence = Field(default_factory=Evidence)


class RunReport(_Frozen):
    """The artifact of one audit: status, controls, findings, and coverage."""

    tool_version: str
    status: RunStatus
    started_at: datetime
    finished_at: datetime | None = None
    target: str = ""
    scoping_mode: ScopingMode = ScopingMode.UNKNOWN
    controls: tuple[ControlResult, ...] = ()
    findings: tuple[Finding, ...] = ()
    results: tuple[ProbeResult, ...] = ()
    endpoints_tested: int = 0
    endpoints_discovered: int = 0
    attacks_run: tuple[AttackName, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def controls_passed(self) -> bool:
        return all(c.passed for c in self.controls)

    @property
    def confirmed(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.confidence is Confidence.CONFIRMED)

    @property
    def suspected(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.confidence is Confidence.SUSPECTED)

    def ranked(self) -> tuple[Finding, ...]:
        """Findings in the order a human should read them."""
        return tuple(sorted(self.findings, key=lambda f: f.sort_key))

    def counts_by_severity(self) -> dict[Severity, int]:
        """Severity histogram over confirmed + suspected findings."""
        counts = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def worst_confirmed(self) -> Severity | None:
        """Highest severity among confirmed findings — what the CI gate reads."""
        confirmed = self.confirmed
        if not confirmed:
            return None
        return max((f.severity for f in confirmed), key=lambda s: s.rank)


def sort_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Rank findings for display: severity, then confidence, then location."""
    return sorted(findings, key=lambda f: f.sort_key)
