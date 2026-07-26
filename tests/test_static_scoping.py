"""Tests for scoping-mode detection.

Getting the mode wrong inverts the rule set, so these tests are less about
coverage than about one claim: the two fixture applications, which differ in
exactly one dimension, are told apart correctly and for the stated reasons.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tenanttrace.core.config import Config, TargetConfig, TenancyConfig
from tenanttrace.core.models import ScopingMode
from tenanttrace.static.base import ParsedFile, ScopingSignal
from tenanttrace.static.engine import parse_file
from tenanttrace.static.scoping import (
    ScopingEvidence,
    decide,
    detect_scoping,
    resolve_scoping,
    scope_mixin_names,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE = REPO_ROOT / "fixtures" / "vulnerable_app"
SAFE = REPO_ROOT / "fixtures" / "safe_app"

TENANT_COLUMNS = ("tenant_id", "company_id", "org_id", "account_id")


def load_tree(directory: Path) -> list[ParsedFile]:
    """Parse every Python file in ``directory``. Parsing only — never imports."""
    return [
        parse_file(path, path.relative_to(REPO_ROOT).as_posix())
        for path in sorted(directory.rglob("*.py"))
    ]


def synthetic(source: str, rel_path: str = "app/thing.py") -> ParsedFile:
    return ParsedFile(path=Path(rel_path), rel_path=rel_path, source=source, tree=ast.parse(source))


def make_config(scoping_mode: str = "auto") -> Config:
    return Config(
        target=TargetConfig(base_url="http://127.0.0.1:8000"),
        tenancy=TenancyConfig(scoping_mode=scoping_mode),
    )


# --------------------------------------------------------------------------- #
# The fixtures — the claim that matters
# --------------------------------------------------------------------------- #
def test_vulnerable_app_is_detected_as_manual():
    signal = detect_scoping(load_tree(VULNERABLE), tenant_columns=TENANT_COLUMNS)
    assert signal.mode is ScopingMode.MANUAL
    assert signal.confidence > 0
    assert any("by hand" in reason for reason in signal.reasons)


def test_safe_app_is_detected_as_global():
    signal = detect_scoping(load_tree(SAFE), tenant_columns=TENANT_COLUMNS)
    assert signal.mode is ScopingMode.GLOBAL
    assert signal.confidence >= 0.5
    joined = " ".join(signal.reasons)
    assert "with_loader_criteria" in joined
    assert "do_orm_execute" in joined


def test_safe_app_exposes_its_scoping_mixin():
    """The mixin name is what UNSCOPED_MODEL needs to have something to miss."""
    assert "TenantScoped" in scope_mixin_names(load_tree(SAFE))


def test_a_signal_always_explains_itself():
    for directory in (VULNERABLE, SAFE):
        signal = detect_scoping(load_tree(directory), tenant_columns=TENANT_COLUMNS)
        assert signal.reasons, f"{directory} produced a verdict with no reasons"
        assert signal.describe()


# --------------------------------------------------------------------------- #
# The rule ladder
# --------------------------------------------------------------------------- #
def test_no_evidence_is_unknown_not_a_guess():
    signal = decide([])
    assert signal.mode is ScopingMode.UNKNOWN
    assert signal.confidence == 0.0
    assert "not enough evidence" in signal.reasons[0]


def test_conflicting_evidence_is_unknown():
    signal = decide(
        [
            ScopingEvidence(ScopingMode.GLOBAL, 0.8, "a global mechanism exists"),
            ScopingEvidence(ScopingMode.MANUAL, 0.9, "and yet everything filters by hand"),
        ]
    )
    assert signal.mode is ScopingMode.UNKNOWN
    assert "conflict" in signal.reasons[0]
    assert "a global mechanism exists" in signal.reasons


def test_a_weak_global_hint_does_not_outvote_manual_practice():
    """A mixin on its own is a naming convention, not a mechanism."""
    signal = decide(
        [
            ScopingEvidence(ScopingMode.GLOBAL, 0.10, "a model inherits TenantScoped"),
            ScopingEvidence(ScopingMode.MANUAL, 0.45, "three queries filter by hand"),
        ]
    )
    assert signal.mode is ScopingMode.MANUAL


def test_a_global_mechanism_outvotes_a_few_hand_written_filters():
    signal = decide(
        [
            ScopingEvidence(ScopingMode.GLOBAL, 0.80, "with_loader_criteria is installed"),
            ScopingEvidence(ScopingMode.MANUAL, 0.30, "one query filters by hand"),
        ]
    )
    assert signal.mode is ScopingMode.GLOBAL


@pytest.mark.parametrize(
    ("source", "expected_marker"),
    [
        (
            "from x import with_loader_criteria\nwith_loader_criteria(M, f)\n",
            "with_loader_criteria",
        ),
        ('@event.listens_for(fac, "do_orm_execute")\ndef h(s):\n    pass\n', "do_orm_execute"),
        ('from contextvars import ContextVar\nv = ContextVar("current_tenant")\n', "ContextVar"),
        ("class Invoice(TenantScoped, Base):\n    pass\n", "TenantScoped"),
        (
            "class Invoice(Base):\n    def boot(self):\n        addGlobalScope(TenantScope)\n",
            "addGlobalScope",
        ),
    ],
)
def test_each_global_marker_is_recognised(source: str, expected_marker: str):
    signal = detect_scoping([synthetic(source)], tenant_columns=TENANT_COLUMNS)
    assert expected_marker in " ".join(signal.reasons)


def test_inline_predicates_are_counted_as_manual_evidence():
    source = (
        "def a(s, t):\n"
        "    return s.scalars(select(Invoice).where(Invoice.tenant_id == t)).all()\n"
        "def b(s, t):\n"
        "    return s.query(Doc).filter_by(tenant_id=t).all()\n"
        "def c(s, t):\n"
        "    return s.query(Cust).filter(Cust.tenant_id == t).all()\n"
    )
    signal = detect_scoping([synthetic(source)], tenant_columns=TENANT_COLUMNS)
    assert signal.mode is ScopingMode.MANUAL
    assert "3 queries" in " ".join(signal.reasons)


def test_a_filter_without_a_tenant_column_is_not_manual_evidence():
    source = "def a(s):\n    return s.scalars(select(Invoice).where(Invoice.id == 1)).all()\n"
    signal = detect_scoping([synthetic(source)], tenant_columns=TENANT_COLUMNS)
    assert signal.mode is ScopingMode.UNKNOWN


# --------------------------------------------------------------------------- #
# Config override
# --------------------------------------------------------------------------- #
def test_auto_defers_to_detection():
    detected = ScopingSignal(ScopingMode.MANUAL, 0.6, ("detected",))
    assert resolve_scoping(make_config("auto"), detected) is detected


@pytest.mark.parametrize("configured", ["manual", "global"])
def test_an_explicit_mode_overrides_detection(configured: str):
    detected = ScopingSignal(ScopingMode.GLOBAL, 0.9, ("a mechanism was found",))
    resolved = resolve_scoping(make_config(configured), detected)
    assert resolved.mode is ScopingMode(configured)
    assert resolved.confidence == 1.0
    assert "overrides detection" in resolved.reasons[0]
    # The override still reports what detection thought, so a mistaken override
    # is visible in the report instead of silently winning.
    assert any("detection would have said" in reason for reason in resolved.reasons)
