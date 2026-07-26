"""Severity, standards tags, and remediation templates — one table per category.

Keeping this in a single table means a new attack module declares what it
found and inherits how that gets rated, tagged, and explained. Nothing
downstream invents a severity of its own.

Severity here is the *inherent* severity of the category. Confidence is
tracked separately and never discounts severity: a suspected critical is still
a critical that we are unsure about, and flattening the two would let a
hypothesis quietly disappear below a CI threshold.
"""

from __future__ import annotations

from dataclasses import dataclass
from string import Template

from tenanttrace.core.models import Category, Confidence, Finding, Severity

__all__ = [
    "CATEGORY_RULES",
    "CategoryRule",
    "describe",
    "remediation_for",
    "severity_for",
    "tags_for",
]


@dataclass(frozen=True, slots=True)
class CategoryRule:
    """How one finding category is rated, tagged, titled, and fixed."""

    severity: Severity
    cwe: tuple[str, ...]
    owasp_api: str
    asvs: str
    title: Template
    remediation: Template

    @property
    def tags(self) -> tuple[str, ...]:
        return (*self.cwe, self.owasp_api, self.asvs)


# Remediation text is deliberately opinionated about *where* the fix goes.
# "Add a filter to this route" is the fix that gets forgotten on the next
# route; the repository/query boundary is the fix that holds.
CATEGORY_RULES: dict[Category, CategoryRule] = {
    Category.CROSS_TENANT_READ: CategoryRule(
        severity=Severity.CRITICAL,
        cwe=("CWE-639",),
        owasp_api="OWASP-API1:2023",
        asvs="ASVS-V4.2.1",
        title=Template("Cross-tenant read on $location"),
        remediation=Template(
            "`$location` returns an object owned by another tenant. The lookup "
            "resolves the identifier without constraining it to the caller's "
            "tenant, so any tenant holding a valid id can read the record.\n\n"
            "Fix it at the data-access boundary, not in the route handler:\n\n"
            "```python\n"
            "# before — the id is trusted on its own\n"
            "obj = session.get($model, obj_id)\n\n"
            "# after — identity is (tenant, id), never id alone\n"
            "obj = session.scalars(\n"
            "    select($model)\n"
            "    .where($model.id == obj_id)\n"
            "    .where($model.$column == ctx.$column)\n"
            ").one_or_none()\n"
            "```\n\n"
            "Better still, make the unsafe call unavailable: put the tenant "
            "predicate in a repository method or a SQLAlchemy "
            "`with_loader_criteria` global scope so a future route cannot "
            "forget it. Return 404 rather than 403 for another tenant's object "
            "so the response does not confirm that the id exists."
        ),
    ),
    Category.CROSS_TENANT_WRITE: CategoryRule(
        severity=Severity.CRITICAL,
        cwe=("CWE-639", "CWE-915"),
        owasp_api="OWASP-API3:2023",
        asvs="ASVS-V4.2.1",
        title=Template("Cross-tenant write via $location"),
        remediation=Template(
            "`$location` accepts a client-supplied `$column` and writes the "
            "record into another tenant. Mass assignment binds the whole "
            "request body onto the model, so any column the model exposes is "
            "attacker-controlled.\n\n"
            "Bind an explicit input schema that simply does not contain the "
            "ownership column, and set it from the authenticated context:\n\n"
            "```python\n"
            "class $model" + "Create(BaseModel):\n"
            "    model_config = ConfigDict(extra='forbid')  # reject unknown keys\n"
            "    title: str\n"
            "    amount: int\n"
            "    # NOTE: no $column here — ownership is never client input\n\n"
            "obj = $model(**payload.model_dump(), $column=ctx.$column)\n"
            "```\n\n"
            "Apply the same rule to updates: an update must never be able to "
            "move a record between tenants."
        ),
    ),
    Category.LISTING_LEAK: CategoryRule(
        severity=Severity.CRITICAL,
        cwe=("CWE-200",),
        owasp_api="OWASP-API1:2023",
        asvs="ASVS-V4.2.1",
        title=Template("Collection at $location returns other tenants' rows"),
        remediation=Template(
            "`$location` lists rows belonging to every tenant. A collection "
            "query without a tenant predicate leaks in bulk, which is strictly "
            "worse than a single-object leak: the caller does not even need to "
            "guess an id.\n\n"
            "```python\n"
            "# before\n"
            "rows = session.scalars(select($model)).all()\n\n"
            "# after\n"
            "rows = session.scalars(\n"
            "    select($model).where($model.$column == ctx.$column)\n"
            ").all()\n"
            "```\n\n"
            "Add a regression test that seeds two tenants and asserts the list "
            "length for one of them — a single-tenant test suite cannot catch "
            "this class of bug."
        ),
    ),
    Category.AGGREGATE_LEAK: CategoryRule(
        severity=Severity.HIGH,
        cwe=("CWE-200",),
        owasp_api="OWASP-API1:2023",
        asvs="ASVS-V4.2.1",
        title=Template("Aggregate at $location counts other tenants' rows"),
        remediation=Template(
            "`$location` computes its aggregate over the whole table. No row "
            "content crosses the boundary, but counts and sums disclose "
            "another tenant's volume — and this is usually the same missing "
            "predicate that will leak rows on the next endpoint.\n\n"
            "```python\n"
            "# before\n"
            "total = session.scalar(select(func.count()).select_from($model))\n\n"
            "# after\n"
            "total = session.scalar(\n"
            "    select(func.count())\n"
            "    .select_from($model)\n"
            "    .where($model.$column == ctx.$column)\n"
            ")\n"
            "```\n\n"
            "Aggregates are routinely written outside the repository layer, so "
            "grep for `func.count`, `func.sum`, and raw `COUNT(` after fixing "
            "this one."
        ),
    ),
    Category.PARAM_OVERRIDE: CategoryRule(
        severity=Severity.CRITICAL,
        cwe=("CWE-639", "CWE-807"),
        owasp_api="OWASP-API1:2023",
        asvs="ASVS-V4.2.1",
        title=Template("Client-supplied tenant honoured at $location"),
        remediation=Template(
            "`$location` takes the tenant from the request instead of from the "
            "authenticated session. Changing one parameter switches tenants, "
            "which makes every other isolation control on this endpoint "
            "irrelevant.\n\n"
            "The tenant must be derived from the credential and from nowhere "
            "else:\n\n"
            "```python\n"
            "# before — the caller chooses\n"
            "def list_items(tenant_id: str | None = None, ctx = Depends(current)):\n"
            "    scope = tenant_id or ctx.$column\n\n"
            "# after — the credential chooses\n"
            "def list_items(ctx = Depends(current)):\n"
            "    scope = ctx.$column\n"
            "```\n\n"
            "If an internal caller genuinely needs to select a tenant, that is "
            "a separate, explicitly authorised admin endpoint — and it belongs "
            "in `cross_tenant_allowlist`, not in the tenant-facing route."
        ),
    ),
    Category.CACHE_KEY_LEAK: CategoryRule(
        severity=Severity.HIGH,
        cwe=("CWE-524",),
        owasp_api="OWASP-API1:2023",
        asvs="ASVS-V8.1.1",
        title=Template("Tenant-less cache key serves another tenant at $location"),
        remediation=Template(
            "`$location` queries correctly but caches the result under a key "
            "that omits the tenant. Whoever populates the entry first wins, so "
            "the leak is intermittent and load-dependent — the worst kind to "
            "reproduce, and invisible to a correct-looking query.\n\n"
            "```python\n"
            "# before\n"
            'key = f"invoice:{obj_id}"\n\n'
            "# after — ownership is part of identity, in the cache too\n"
            'key = f"invoice:{ctx.$column}:{obj_id}"\n'
            "```\n\n"
            "Centralise key construction in one helper that takes the tenant "
            "as a required argument, so a caller cannot omit it. The same rule "
            "applies to background-job payloads, rate-limit buckets, and "
            "memoised lookups."
        ),
    ),
    Category.MISSING_TENANT_FILTER: CategoryRule(
        severity=Severity.HIGH,
        cwe=("CWE-639",),
        owasp_api="OWASP-API1:2023",
        asvs="ASVS-V4.2.1",
        title=Template("Query on a tenant-scoped model with no tenant predicate at $location"),
        remediation=Template(
            "A query against a tenant-scoped model at `$location` carries no "
            "`$column` predicate. This is a hypothesis from the static engine, "
            "not a proven leak — the filter may be applied by a caller, a "
            "repository wrapper, or a scope this analysis cannot see.\n\n"
            "Confirm it by probing the endpoint that reaches this code. If the "
            "prober confirms it, apply the tenant predicate at the query "
            "itself rather than upstream, so the guarantee is local and "
            "survives refactoring."
        ),
    ),
    Category.RAW_SQL_ESCAPE: CategoryRule(
        severity=Severity.HIGH,
        cwe=("CWE-284",),
        owasp_api="OWASP-API1:2023",
        asvs="ASVS-V4.1.3",
        title=Template("Raw SQL bypasses the global tenant scope at $location"),
        remediation=Template(
            "`$location` executes raw SQL. In an application relying on a "
            "global scope (an ORM event hook, `with_loader_criteria`, or a "
            "base-class filter) raw SQL runs outside that mechanism, so the "
            "isolation guarantee simply does not apply to this statement.\n\n"
            "Either express the query through the ORM so the scope attaches, "
            "or add the tenant predicate explicitly and bind it as a "
            "parameter:\n\n"
            "```python\n"
            "session.execute(\n"
            '    text("SELECT ... FROM invoices WHERE $column = :tenant"),\n'
            '    {"tenant": ctx.$column},\n'
            ")\n"
            "```\n\n"
            "Then add a lint rule or a review checklist item for `text(` — raw "
            "SQL is where global scoping quietly stops being true."
        ),
    ),
    Category.SCOPE_BYPASS_FLAG: CategoryRule(
        severity=Severity.HIGH,
        cwe=("CWE-284",),
        owasp_api="OWASP-API1:2023",
        asvs="ASVS-V4.1.3",
        title=Template("Explicit tenant-scope bypass at $location"),
        remediation=Template(
            "`$location` disables the global tenant scope explicitly. That is "
            "sometimes correct — platform admin tooling, migrations, "
            "cross-tenant reporting — and sometimes a shortcut that shipped.\n\n"
            "Make each bypass deliberate and reviewable: keep them in a small "
            "number of clearly named modules, require an authorisation check "
            "next to the bypass, and list the endpoints that legitimately "
            "cross tenants in `cross_tenant_allowlist` so this tool stops "
            "reporting them."
        ),
    ),
    Category.UNSCOPED_MODEL: CategoryRule(
        severity=Severity.MEDIUM,
        cwe=("CWE-284",),
        owasp_api="OWASP-API1:2023",
        asvs="ASVS-V4.1.3",
        title=Template("Tenant-owned model outside the global scope at $location"),
        remediation=Template(
            "`$location` defines a model that carries tenant-owned data but "
            "does not participate in the global scoping mechanism (it lacks "
            "the scoping mixin or base class). Every query against it is "
            "unscoped by default, so isolation depends on each caller "
            "remembering.\n\n"
            "Add the model to the scoping mechanism, or — if it genuinely is "
            "shared reference data — document that and remove it from "
            "`scoped_models` so this stops being reported."
        ),
    ),
    Category.TENANTLESS_CACHE_KEY: CategoryRule(
        severity=Severity.MEDIUM,
        cwe=("CWE-524",),
        owasp_api="OWASP-API1:2023",
        asvs="ASVS-V8.1.1",
        title=Template("Cache key built without a tenant component at $location"),
        remediation=Template(
            "The cache key built at `$location` interpolates an object id but "
            "no tenant. If two tenants can address the same id space — or if "
            "the id is guessable — one tenant's cached value is served to "
            "another.\n\n"
            "Include the tenant in the key, and route all key construction "
            "through a helper that requires it as an argument."
        ),
    ),
    Category.TENANTLESS_JOB_PAYLOAD: CategoryRule(
        severity=Severity.MEDIUM,
        cwe=("CWE-639",),
        owasp_api="OWASP-API1:2023",
        asvs="ASVS-V4.2.1",
        title=Template("Background job dispatched without tenant context at $location"),
        remediation=Template(
            "The task dispatched at `$location` does not carry the tenant in "
            "its payload. The worker therefore re-derives scope from somewhere "
            "else — a default, a global, or nothing at all — and background "
            "work is exactly where an HTTP-level audit cannot see the result.\n\n"
            "Pass the tenant explicitly in the payload and have the worker "
            "establish the same scoped context the request handler uses."
        ),
    ),
    Category.HARNESS_ERROR: CategoryRule(
        severity=Severity.INFO,
        cwe=(),
        owasp_api="",
        asvs="",
        title=Template("Harness error at $location"),
        remediation=Template(
            "The run could not complete a check at `$location`. This is a "
            "problem with the audit, not necessarily with the application — "
            "fix the harness and re-run before drawing any conclusion."
        ),
    ),
}


def severity_for(category: Category) -> Severity:
    """Inherent severity of a category."""
    return CATEGORY_RULES[category].severity


def tags_for(category: Category) -> tuple[str, ...]:
    """CWE / OWASP-API / ASVS tags, with empty entries dropped."""
    return tuple(t for t in CATEGORY_RULES[category].tags if t)


def title_for(category: Category, location: str) -> str:
    """Human-readable finding title for a category at a location."""
    return CATEGORY_RULES[category].title.safe_substitute(location=location)


def remediation_for(
    category: Category,
    *,
    location: str,
    model: str = "Model",
    column: str = "tenant_id",
) -> str:
    """Render the remediation template with this application's own names.

    Generic advice gets skimmed; advice naming the reader's model and column
    gets applied. Missing placeholders are left intact rather than raising —
    a partially-parameterised fix is still more useful than no fix.
    """
    return CATEGORY_RULES[category].remediation.safe_substitute(
        location=location,
        model=model,
        column=column,
    )


def describe(finding: Finding) -> str:
    """One-line summary used in terminal output and PR comments."""
    marker = "✗" if finding.confidence is Confidence.CONFIRMED else "?"
    return f"{marker} [{finding.severity.value}/{finding.confidence.value}] {finding.title}"
