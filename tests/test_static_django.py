"""The second adapter — and what having one proves.

`LanguageAdapter` had a single implementation for its whole life, which is a
Protocol nobody has tested. Writing this one moved two rounds of code out of
the SQLAlchemy adapter into shared modules (ADR-0012); what is asserted here is
that the Django half is genuinely Django-shaped, and that the shared half still
fires from a second caller.

Precision matters more than recall in these tests. Django applications scope
correctly in several ordinary ways, and a rule that flagged them all would make
the static engine noise — which is the failure mode CLAUDE.md names first.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tenanttrace.core.models import Category, Confidence, Engine, ScopingMode
from tenanttrace.static.adapters.python_django import ADAPTER_NAME, PythonDjangoAdapter
from tenanttrace.static.base import ParsedFile, StaticContext
from tenanttrace.static.registry import available, resolve


def parse(source: str, name: str = "views.py") -> ParsedFile:
    return ParsedFile(path=Path(name), rel_path=name, source=source, tree=ast.parse(source))


def findings(source: str, *, mode: ScopingMode = ScopingMode.MANUAL) -> list:
    ctx = StaticContext(mode=mode)
    return list(PythonDjangoAdapter().find_findings(parse(source), ctx))


def categories(source: str, **kwargs: object) -> list[Category]:
    return [f.category for f in findings(source, **kwargs)]  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# What Django does differently
# --------------------------------------------------------------------------- #


def test_a_manager_query_with_no_tenant_predicate_is_a_hypothesis() -> None:
    assert categories("Invoice.objects.filter(status='open')") == [Category.MISSING_TENANT_FILTER]


def test_the_404_shortcut_hides_a_query_and_is_still_caught() -> None:
    """get_object_or_404(Model, pk=…) is the canonical Django BOLA."""
    source = "from django.shortcuts import get_object_or_404\nget_object_or_404(Invoice, pk=1)\n"
    assert Category.MISSING_TENANT_FILTER in categories(source)


@pytest.mark.parametrize(
    "source",
    [
        "Invoice.objects.filter(tenant=request.tenant)",
        "Invoice.objects.filter(tenant_id=t, status='open')",
        "Invoice.objects.filter(organization__slug=slug)",
        "Invoice.objects.filter(status='open').filter(tenant=t)",
        "Invoice.objects.filter(tenant=t).get(pk=1)",
        "get_object_or_404(Invoice.objects.filter(tenant=t), pk=1)",
    ],
)
def test_the_ordinary_ways_django_scopes_correctly_are_not_flagged(source: str) -> None:
    """A rule that fired on all of these would make the engine noise."""
    assert Category.MISSING_TENANT_FILTER not in categories(source)


def test_raw_and_extra_are_djangos_raw_sql() -> None:
    assert Category.RAW_SQL_ESCAPE in categories(
        "Invoice.objects.raw('SELECT * FROM invoice WHERE id = %s', [pk])"
    )


def test_a_raw_query_that_binds_the_tenant_is_left_alone() -> None:
    assert Category.RAW_SQL_ESCAPE not in categories(
        "Invoice.objects.raw('SELECT * FROM invoice WHERE tenant_id = %s', [tenant_id])"
    )


@pytest.mark.parametrize(
    "source",
    ["Invoice._base_manager.all()", "Invoice.all_objects.get(pk=1)", "unfiltered(Invoice)"],
)
def test_stepping_around_a_scoped_manager_is_reported_under_global_scoping(source: str) -> None:
    assert Category.SCOPE_BYPASS_FLAG in categories(source, mode=ScopingMode.GLOBAL)


def test_manager_rules_are_silent_under_global_scoping() -> None:
    """If the default manager scopes every query, an unfiltered call is normal."""
    assert Category.MISSING_TENANT_FILTER not in categories(
        "Invoice.objects.filter(status='open')", mode=ScopingMode.GLOBAL
    )


# --------------------------------------------------------------------------- #
# The shared half still fires from a second caller
# --------------------------------------------------------------------------- #


def test_the_language_rules_reach_the_second_adapter() -> None:
    """These live in static/rules.py precisely so both adapters get them."""
    source = "cache.set(f'invoice:{invoice.id}', payload)\n"
    assert Category.TENANTLESS_CACHE_KEY in categories(source)


def test_job_payloads_reach_the_second_adapter() -> None:
    assert Category.TENANTLESS_JOB_PAYLOAD in categories(
        "export_invoices.delay({'invoice_id': invoice.id})"
    )


# --------------------------------------------------------------------------- #
# Contract
# --------------------------------------------------------------------------- #


def test_every_finding_is_a_hypothesis_from_the_static_engine() -> None:
    """Rule 3: the static engine never emits a standalone verdict."""
    for finding in findings("Invoice.objects.filter(status='open')"):
        assert finding.confidence is Confidence.SUSPECTED
        assert finding.engine is Engine.STATIC
        assert "::" in finding.location


def test_every_finding_states_what_it_assumed() -> None:
    for finding in findings("get_object_or_404(Invoice, pk=1)"):
        assert finding.evidence.assumption
        assert "wrong when" in finding.evidence.assumption


def test_the_adapter_is_registered_and_auto_detectable() -> None:
    assert ADAPTER_NAME in available()
    django = parse("from django.db import models\n", "models.py")
    assert resolve("auto", [django]).name == ADAPTER_NAME


def test_a_sqlalchemy_tree_does_not_resolve_to_django() -> None:
    """A clever guess that analysed one framework with the other's rules would
    produce confident nonsense."""
    alchemy = parse("from sqlalchemy import select\n", "repo.py")
    assert resolve("auto", [alchemy]).name != ADAPTER_NAME
