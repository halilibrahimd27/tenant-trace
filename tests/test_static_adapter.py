"""Tests for the Python/SQLAlchemy adapter and the scan engine.

The fixture applications are the corpus: the vulnerable app is the recall test
and the safe app is the precision test. Everything else here defends a rule the
component is not allowed to break — never execute what it reads, never crash on
source it cannot parse, never emit a verdict, never put a line number in a
location.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from tenanttrace.core.config import Config, StaticConfig, TargetConfig, TenancyConfig
from tenanttrace.core.models import Category, Confidence, Engine, Finding, ScopingMode
from tenanttrace.core.severity import severity_for
from tenanttrace.static import registry
from tenanttrace.static.adapters.python_sqlalchemy import PythonSQLAlchemyAdapter
from tenanttrace.static.base import LanguageAdapter, StaticContext
from tenanttrace.static.engine import StaticScanResult, scan

REPO_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE = "fixtures/vulnerable_app"
SAFE = "fixtures/safe_app"

SCOPED_MODELS = ("Invoice", "Document", "Customer")

# Categories that mean the same thing whichever way the application scopes.
MODE_INDEPENDENT = {
    Category.RAW_SQL_ESCAPE,
    Category.TENANTLESS_CACHE_KEY,
    Category.TENANTLESS_JOB_PAYLOAD,
}


@pytest.fixture(autouse=True)
def _run_from_repo_root(monkeypatch: pytest.MonkeyPatch):
    """Locations are anchored to the working directory, so pin it."""
    monkeypatch.chdir(REPO_ROOT)


def make_config(
    *,
    adapter: str = "python_sqlalchemy",
    scoped_models: tuple[str, ...] = SCOPED_MODELS,
    scoping_mode: str = "auto",
    allowlist: tuple[str, ...] = (),
    exclude_globs: tuple[str, ...] = ("**/migrations/**",),
) -> Config:
    return Config(
        target=TargetConfig(base_url="http://127.0.0.1:8000"),
        tenancy=TenancyConfig(
            scoped_models=scoped_models,
            scoping_mode=scoping_mode,
            cross_tenant_allowlist=allowlist,
        ),
        static=StaticConfig(adapter=adapter, exclude_globs=exclude_globs),
    )


def located(result: StaticScanResult) -> set[tuple[Category, str]]:
    return {(f.category, f.location) for f in result.findings}


def scan_source(source: str, tmp_path: Path, **kwargs: object) -> StaticScanResult:
    """Write one module to disk and scan it. Nothing here is ever imported."""
    (tmp_path / "app.py").write_text(textwrap.dedent(source), encoding="utf-8")
    return scan(tmp_path, make_config(**kwargs))  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Recall: the vulnerable fixture
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def vulnerable() -> StaticScanResult:
    return scan(
        REPO_ROOT / VULNERABLE,
        Config(
            target=TargetConfig(base_url="http://127.0.0.1:8000"),
            tenancy=TenancyConfig(scoped_models=SCOPED_MODELS),
            static=StaticConfig(adapter="python_sqlalchemy"),
        ),
    )


def test_vulnerable_app_scans_as_manual(vulnerable: StaticScanResult):
    assert vulnerable.scoping.mode is ScopingMode.MANUAL
    assert vulnerable.files_scanned >= 4


def test_static_only_holes_are_found(vulnerable: StaticScanResult):
    """S1 and S2 — the code no HTTP route reaches, which is the whole point."""
    found = located(vulnerable)
    assert (
        Category.RAW_SQL_ESCAPE,
        f"{VULNERABLE}/reports.py::monthly_revenue_report",
    ) in found
    assert (
        Category.TENANTLESS_JOB_PAYLOAD,
        f"{VULNERABLE}/jobs.py::enqueue_invoice_export",
    ) in found
    assert (
        Category.TENANTLESS_CACHE_KEY,
        f"{VULNERABLE}/jobs.py::enqueue_invoice_export",
    ) in found


def test_the_http_holes_the_static_engine_can_see_are_found(vulnerable: StaticScanResult):
    """H1, H2, H3 and H5 have a source-level shape; H4 and H6 do not."""
    found = located(vulnerable)
    assert (Category.MISSING_TENANT_FILTER, f"{VULNERABLE}/routes.py::get_invoice") in found
    assert (Category.MISSING_TENANT_FILTER, f"{VULNERABLE}/routes.py::list_documents") in found
    assert (Category.MISSING_TENANT_FILTER, f"{VULNERABLE}/routes.py::get_stats") in found
    assert (Category.TENANTLESS_CACHE_KEY, f"{VULNERABLE}/routes.py::get_document") in found


@pytest.mark.parametrize(
    "symbol",
    [
        "routes.py::list_invoices",  # N1 — correctly scoped list
        "routes.py::create_document",  # N2 — ownership from the credential
        "routes.py::delete_invoice",  # N3 — scoped lookup before the delete
        "reports.py::revenue_for_tenant",  # raw SQL, but the tenant is bound
    ],
)
def test_negative_controls_inside_the_vulnerable_app_stay_clean(
    vulnerable: StaticScanResult, symbol: str
):
    location = f"{VULNERABLE}/{symbol}"
    assert not [f for f in vulnerable.findings if f.location == location]


def test_every_static_label_in_labels_yaml_is_reported(vulnerable: StaticScanResult):
    """Recall against the answer key, for the entries marked ``engine: static``."""
    labels = yaml.safe_load((REPO_ROOT / "fixtures" / "labels.yaml").read_text(encoding="utf-8"))
    expected = [
        entry
        for entry in labels["targets"]["vulnerable_app"]["expected"]
        if entry.get("engine") == "static"
    ]
    assert expected, "labels.yaml has no static entries; this test would prove nothing"

    found = located(vulnerable)
    for entry in expected:
        pair = (Category(entry["category"]), entry["location"])
        assert pair in found, f"{entry['id']} was not reported: {pair}"


def test_findings_are_hypotheses_not_verdicts(vulnerable: StaticScanResult):
    """CLAUDE.md rule 3 — the static engine never produces a standalone verdict."""
    assert vulnerable.findings
    for finding in vulnerable.findings:
        assert finding.confidence is Confidence.SUSPECTED
        assert finding.engine is Engine.STATIC
        assert not finding.gates_ci
        assert finding.severity is severity_for(finding.category)


def test_every_finding_carries_its_assumption_and_its_evidence(vulnerable: StaticScanResult):
    for finding in vulnerable.findings:
        assert finding.evidence.assumption, f"{finding.location} states no assumption"
        assert "wrong" in finding.evidence.assumption.lower()
        assert finding.evidence.file
        assert finding.evidence.line and finding.evidence.line > 0
        assert finding.evidence.snippet
        assert finding.evidence.note
        assert finding.remediation
        assert finding.tags


def test_locations_are_file_and_symbol_never_a_line_number(vulnerable: StaticScanResult):
    """A line number in a location would expire every baseline on every edit."""
    for finding in vulnerable.findings:
        file_part, separator, symbol = finding.location.partition("::")
        assert separator == "::", finding.location
        assert file_part.endswith(".py")
        assert symbol and not symbol.isdigit()
        assert str(finding.evidence.line) not in finding.location


def test_fingerprints_are_attached_and_distinct(vulnerable: StaticScanResult):
    fingerprints = [f.fingerprint for f in vulnerable.findings]
    assert all(fp.startswith("sha256:") for fp in fingerprints)
    assert len(set(fingerprints)) == len(fingerprints)


def test_one_finding_per_category_per_symbol(vulnerable: StaticScanResult):
    """Three unscoped aggregates in one handler are one thing to fix."""
    seen = [(f.category, f.location) for f in vulnerable.findings]
    assert len(set(seen)) == len(seen)


# --------------------------------------------------------------------------- #
# Precision: the safe fixture
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def safe() -> StaticScanResult:
    return scan(
        REPO_ROOT / SAFE,
        Config(
            target=TargetConfig(base_url="http://127.0.0.1:8000"),
            tenancy=TenancyConfig(scoped_models=SCOPED_MODELS),
            static=StaticConfig(adapter="python_sqlalchemy"),
        ),
    )


def test_safe_app_scans_as_global(safe: StaticScanResult):
    assert safe.scoping.mode is ScopingMode.GLOBAL


def test_safe_app_reports_nothing_except_the_named_admin_bypass(safe: StaticScanResult):
    """Every finding against the safe app is a false positive by construction."""
    allowed = {(Category.SCOPE_BYPASS_FLAG, f"{SAFE}/routes.py::admin_all_invoices")}
    assert located(safe) <= allowed


def test_the_admin_bypass_can_be_allowlisted():
    result = scan(
        REPO_ROOT / SAFE,
        make_config(allowlist=("*::admin_*",)),
    )
    assert result.findings == ()


def test_global_mode_never_reports_a_missing_filter(safe: StaticScanResult):
    """In Mode B a handler with no tenant predicate is correct, not a bug."""
    assert all(f.category is not Category.MISSING_TENANT_FILTER for f in safe.findings)


# --------------------------------------------------------------------------- #
# Mode-specific rules
# --------------------------------------------------------------------------- #
def test_unknown_mode_emits_only_mode_independent_findings(tmp_path: Path):
    source = """
        from sqlalchemy import select, text

        def report(session, cache, invoice_id):
            rows = session.scalars(select(Invoice)).all()
            session.execute(text("SELECT id FROM invoices"))
            cache.set(f"inv:{invoice_id}", "x")
            return rows
    """
    result = scan_source(source, tmp_path)
    assert result.scoping.mode is ScopingMode.UNKNOWN
    assert {f.category for f in result.findings} <= MODE_INDEPENDENT
    assert any("scoping mode is unknown" in w for w in result.warnings)


def test_an_explicit_mode_unlocks_the_mode_specific_rules(tmp_path: Path):
    source = """
        from sqlalchemy import select

        def listing(session):
            return session.scalars(select(Invoice)).all()
    """
    result = scan_source(source, tmp_path, scoping_mode="manual")
    assert {f.category for f in result.findings} == {Category.MISSING_TENANT_FILTER}


def test_raw_sql_that_binds_the_tenant_is_not_reported(tmp_path: Path):
    source = """
        from sqlalchemy import text

        def total(session, tenant_id):
            return session.execute(
                text("SELECT SUM(amount) FROM invoices WHERE tenant_id = :tenant_id"),
                {"tenant_id": tenant_id},
            ).scalar()
    """
    assert scan_source(source, tmp_path).findings == ()


def test_raw_sql_without_a_table_reference_is_not_reported(tmp_path: Path):
    source = """
        from sqlalchemy import text

        def ping(session):
            return session.execute(text("SELECT 1")).scalar()
    """
    assert scan_source(source, tmp_path).findings == ()


def test_a_cache_key_carrying_the_tenant_is_not_reported(tmp_path: Path):
    source = """
        def read(cache, principal, document_id):
            return cache.get(f"doc:{principal.tenant_id}:{document_id}")
    """
    assert scan_source(source, tmp_path).findings == ()


def test_a_tenantless_cache_key_is_reported_once_per_template(tmp_path: Path):
    """One key namespace is one defect; reporting the reader too is noise."""
    source = """
        def write(cache, invoice_id):
            cache.set(f"export:{invoice_id}", "{}")

        def read(cache, invoice_id):
            return cache.get(f"export:{invoice_id}")
    """
    result = scan_source(source, tmp_path)
    assert [(f.category, f.location) for f in result.findings] == [
        (Category.TENANTLESS_CACHE_KEY, "app.py::write")
    ]


def test_a_contextvar_set_is_not_mistaken_for_a_cache_write(tmp_path: Path):
    source = """
        from contextvars import ContextVar

        _flag = ContextVar("flag", default=False)

        def disable(record_id):
            _flag.set(True)
            return record_id
    """
    assert scan_source(source, tmp_path).findings == ()


def test_a_job_payload_carrying_the_tenant_is_not_reported(tmp_path: Path):
    source = """
        def enqueue_export(queue, invoice_id, tenant_id):
            queue.delay({"invoice_id": invoice_id, "tenant_id": tenant_id})
    """
    assert scan_source(source, tmp_path).findings == ()


def test_a_dispatch_call_with_a_tenantless_payload_is_reported(tmp_path: Path):
    source = """
        def ship(queue, invoice_id):
            queue.apply_async({"invoice_id": invoice_id})
    """
    result = scan_source(source, tmp_path)
    assert [f.category for f in result.findings] == [Category.TENANTLESS_JOB_PAYLOAD]


def test_a_payload_spread_from_an_unseen_dict_is_not_accused(tmp_path: Path):
    """We cannot see inside ``**base``, so we say nothing rather than guess."""
    source = """
        def enqueue_export(queue, base, invoice_id):
            queue.delay({**base, "invoice_id": invoice_id})
    """
    assert scan_source(source, tmp_path).findings == ()


def test_an_unscoped_model_is_reported_in_global_mode(tmp_path: Path):
    source = """
        from sqlalchemy import event
        from sqlalchemy.orm import with_loader_criteria

        class TenantScoped:
            tenant_id = None

        class Invoice(TenantScoped, Base):
            __tablename__ = "invoices"

        class Note(Base):
            __tablename__ = "notes"
            tenant_id = None

        def install(factory):
            @event.listens_for(factory, "do_orm_execute")
            def _apply(state):
                state.statement.options(with_loader_criteria(TenantScoped, None))
    """
    result = scan_source(source, tmp_path, scoped_models=())
    assert (Category.UNSCOPED_MODEL, "app.py::Note") in located(result)
    assert (Category.UNSCOPED_MODEL, "app.py::Invoice") not in located(result)


def test_a_bypass_keyword_is_reported_in_global_mode(tmp_path: Path):
    source = """
        from sqlalchemy.orm import with_loader_criteria

        def install(session):
            with_loader_criteria(TenantScoped, None)

        def report(repo):
            return repo.all_invoices(include_all_tenants=True)

        def honest(repo):
            return repo.all_invoices(include_all_tenants=False)
    """
    result = scan_source(source, tmp_path)
    assert result.scoping.mode is ScopingMode.GLOBAL
    bypasses = {f.location for f in result.findings if f.category is Category.SCOPE_BYPASS_FLAG}
    assert bypasses == {"app.py::report"}


def test_a_query_built_over_two_statements_keeps_its_predicate(tmp_path: Path):
    """One hop of dataflow: the model and the predicate are in different lines."""
    source = """
        from sqlalchemy import select

        def listing(session, principal):
            stmt = select(Invoice)
            stmt = stmt.where(Invoice.tenant_id == principal.tenant_id)
            return session.scalars(stmt).all()
    """
    assert scan_source(source, tmp_path, scoping_mode="manual").findings == ()


def test_session_get_is_a_query_root_but_cache_get_is_not(tmp_path: Path):
    source = """
        def fetch(session, cache, invoice_id):
            cached = cache.get("static-key")
            return cached or session.get(Invoice, invoice_id)
    """
    result = scan_source(source, tmp_path, scoping_mode="manual")
    assert [f.category for f in result.findings] == [Category.MISSING_TENANT_FILTER]


def test_without_configured_models_the_fallback_is_declared(tmp_path: Path):
    source = """
        from sqlalchemy import select

        def listing(session):
            return session.scalars(select(Invoice)).all()
    """
    result = scan_source(source, tmp_path, scoped_models=(), scoping_mode="manual")
    assert [f.category for f in result.findings] == [Category.MISSING_TENANT_FILTER]
    assert "scoped_models" in result.findings[0].evidence.assumption
    assert any("scoped_models" in w for w in result.warnings)


# --------------------------------------------------------------------------- #
# Hostile and broken input
# --------------------------------------------------------------------------- #
def test_a_file_that_does_not_parse_is_skipped_with_a_warning(tmp_path: Path):
    (tmp_path / "broken.py").write_text("def oops(:\n", encoding="utf-8")
    (tmp_path / "fine.py").write_text(
        "from sqlalchemy import text\n\n"
        "def q(s):\n"
        '    return s.execute(text("SELECT id FROM invoices"))\n',
        encoding="utf-8",
    )

    result = scan(tmp_path, make_config())

    assert result.files_scanned == 1
    assert any("broken.py" in w and "does not parse" in w for w in result.warnings)
    assert [f.category for f in result.findings] == [Category.RAW_SQL_ESCAPE]


def test_module_level_code_is_parsed_and_never_executed(tmp_path: Path):
    """CLAUDE.md rule 1. The sentinel exists only if the module ran."""
    sentinel = tmp_path / "sentinel.txt"
    (tmp_path / "hostile.py").write_text(
        "import os\n"
        f"os.system('touch {sentinel}')\n"
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('executed')\n",
        encoding="utf-8",
    )

    result = scan(tmp_path, make_config())

    assert not sentinel.exists(), "the static engine executed the code it was analysing"
    assert result.files_scanned == 1


def test_a_missing_path_is_a_warning_not_a_crash(tmp_path: Path):
    result = scan(tmp_path / "nope", make_config())
    assert result.findings == ()
    assert result.scoping.mode is ScopingMode.UNKNOWN
    assert any("no such file" in w for w in result.warnings)


def test_an_empty_tree_is_a_warning_not_a_clean_bill_of_health(tmp_path: Path):
    result = scan(tmp_path, make_config())
    assert result.findings == ()
    assert any("no analysable source files" in w for w in result.warnings)


def test_an_adapter_that_raises_costs_one_file_not_the_scan(tmp_path: Path, monkeypatch):
    class Exploding(PythonSQLAlchemyAdapter):
        def find_findings(self, file, ctx):
            msg = "rule blew up"
            raise RuntimeError(msg)

    monkeypatch.setitem(registry._FACTORIES, "python_sqlalchemy", Exploding)
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    result = scan(tmp_path, make_config())

    assert result.findings == ()
    assert any("rule blew up" in w for w in result.warnings)


def test_excluded_paths_are_not_scanned(tmp_path: Path):
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "0001.py").write_text(
        "from sqlalchemy import text\n\n"
        "def up(s):\n"
        '    s.execute(text("SELECT * FROM invoices"))\n',
        encoding="utf-8",
    )
    result = scan(tmp_path, make_config())
    assert result.files_scanned == 0
    assert result.findings == ()


def test_locations_stay_relative_for_a_tree_outside_the_working_directory(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        'from sqlalchemy import text\n\ndef q(s):\n    s.execute(text("SELECT * FROM invoices"))\n',
        encoding="utf-8",
    )
    result = scan(tmp_path, make_config())
    assert [f.location for f in result.findings] == ["app.py::q"]


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
def test_the_shipped_adapter_satisfies_the_protocol():
    adapter = registry.get("python_sqlalchemy")
    assert isinstance(adapter, LanguageAdapter)
    assert adapter.name == "python_sqlalchemy"
    assert adapter.file_globs == ("**/*.py",)


def test_auto_resolves_a_sqlalchemy_tree(tmp_path: Path):
    source = """
        from sqlalchemy import text

        def q(session):
            session.execute(text("SELECT id FROM invoices"))
    """
    result = scan_source(source, tmp_path, adapter="auto")
    assert [f.category for f in result.findings] == [Category.RAW_SQL_ESCAPE]


def test_an_unknown_adapter_name_names_the_registered_ones():
    with pytest.raises(registry.UnknownAdapterError, match="python_sqlalchemy"):
        registry.get("cobol_db2")


def test_auto_returns_nothing_when_it_recognises_nothing():
    assert registry.resolve("auto", []) is None


def test_a_registered_adapter_is_discoverable():
    assert "python_sqlalchemy" in registry.available()
    assert "**/*.py" in registry.discovery_globs()


# --------------------------------------------------------------------------- #
# Adapter used directly
# --------------------------------------------------------------------------- #
def test_the_adapter_is_stateless_across_files(tmp_path: Path):
    """Two scans with one adapter instance must not contaminate each other."""
    adapter = PythonSQLAlchemyAdapter()
    ctx = StaticContext(mode=ScopingMode.MANUAL, scoped_models=SCOPED_MODELS)
    from tenanttrace.static.engine import parse_file

    (tmp_path / "a.py").write_text("from sqlalchemy import select\n", encoding="utf-8")
    (tmp_path / "b.py").write_text(
        "from sqlalchemy import select\n\ndef q(s):\n    return s.scalars(select(Invoice)).all()\n",
        encoding="utf-8",
    )
    first = list(adapter.find_findings(parse_file(tmp_path / "a.py", "a.py"), ctx))
    second = list(adapter.find_findings(parse_file(tmp_path / "b.py", "b.py"), ctx))
    third = list(adapter.find_findings(parse_file(tmp_path / "a.py", "a.py"), ctx))

    assert first == []
    assert isinstance(second[0], Finding)
    assert third == []
