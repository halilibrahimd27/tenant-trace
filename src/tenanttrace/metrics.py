"""Score TenantTrace against ``fixtures/labels.yaml``.

This is what turns "I think it works" into a number, and it is a gate: the
build fails when recall drops below the configured floor. Without it, every
accuracy claim in the README would be a feeling.

**What is measured, and why the two metrics are not symmetric.**

*Recall* is measured over every label, dynamic and static alike. A hole we do
not find is a failure regardless of which engine was supposed to find it.

*Precision* is measured over **confirmed** findings only — the ones that can
fail somebody's build. Static findings are hypotheses by construction (rule 3),
and extra hypotheses are the expected cost of a hypothesis generator, so
counting them as false positives would either punish the static engine for
doing its job or push us to make it timid. The one exception is deliberate:
**any finding, of any confidence, at an ``expect_clean`` location is a false
positive.** That is the cry-wolf test — the correctly-scoped list inside the
leaky app, and the admin endpoint that crosses tenants on purpose.

The whole harness runs in-process over ASGI (ADR-0004): no Docker, no Redis, no
network, so the gate is fast and deterministic everywhere.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from tenanttrace._importing import ensure_cwd_importable
from tenanttrace.core.config import Config, load_config
from tenanttrace.core.fingerprint import normalize_path, normalize_source_location
from tenanttrace.core.models import Confidence, Engine, Finding, RunStatus, ScopingMode

__all__ = ["Label", "MetricsReport", "TargetScore", "score_targets"]


@dataclass(frozen=True, slots=True)
class Label:
    """One expected finding from the answer key."""

    id: str
    location: str
    category: str
    severity: str
    engine: str
    attack: str | None = None
    note: str = ""

    @property
    def key(self) -> str:
        return f"{self.id} {self.location} ({self.category})"


@dataclass(frozen=True, slots=True)
class CleanLabel:
    """A location that must produce no finding at all."""

    location: str
    reason: str = ""


@dataclass
class TargetScore:
    """How the tool did against one fixture application."""

    target: str
    expected: tuple[Label, ...] = ()
    matched: list[Label] = field(default_factory=list)
    missed: list[Label] = field(default_factory=list)
    false_positives: list[Finding] = field(default_factory=list)
    confirmed_count: int = 0
    suspected_count: int = 0
    status: RunStatus = RunStatus.VALID
    scoping_expected: ScopingMode = ScopingMode.UNKNOWN
    scoping_detected: ScopingMode = ScopingMode.UNKNOWN
    errors: list[str] = field(default_factory=list)

    @property
    def recall(self) -> float:
        total = len(self.expected)
        return 1.0 if total == 0 else len(self.matched) / total

    @property
    def precision(self) -> float:
        # Denominator is confirmed findings plus any cry-wolf false positive,
        # because those are the two ways a user loses trust in the tool.
        true_positives = sum(1 for label in self.matched if label.engine == "probe")
        denominator = true_positives + len(self.false_positives)
        return 1.0 if denominator == 0 else true_positives / denominator

    @property
    def scoping_ok(self) -> bool:
        if self.scoping_expected is ScopingMode.UNKNOWN:
            return True
        return self.scoping_detected is self.scoping_expected


@dataclass
class MetricsReport:
    """The whole scorecard."""

    targets: list[TargetScore] = field(default_factory=list)
    min_recall: float = 0.90

    @property
    def recall(self) -> float:
        expected = sum(len(t.expected) for t in self.targets)
        matched = sum(len(t.matched) for t in self.targets)
        return 1.0 if expected == 0 else matched / expected

    @property
    def false_positives(self) -> int:
        return sum(len(t.false_positives) for t in self.targets)

    @property
    def passed(self) -> bool:
        return (
            self.recall >= self.min_recall
            and self.false_positives == 0
            and all(t.status is RunStatus.VALID for t in self.targets)
            and all(t.scoping_ok for t in self.targets)
        )

    def render(self) -> str:
        """A confusion matrix a human can read, naming what was missed."""
        lines: list[str] = []
        for target in self.targets:
            lines.append(f"\n── {target.target} " + "─" * max(0, 56 - len(target.target)))
            lines.append(
                f"   run status        {target.status.value.upper()}"
                + ("" if target.status is RunStatus.VALID else "   ← run cannot be trusted")
            )
            if target.scoping_expected is not ScopingMode.UNKNOWN:
                mark = "ok" if target.scoping_ok else "WRONG"
                lines.append(
                    f"   scoping mode      detected {target.scoping_detected.value}, "
                    f"expected {target.scoping_expected.value}  [{mark}]"
                )
            lines.append(
                f"   labels            {len(target.matched)}/{len(target.expected)} found"
                f"   (recall {target.recall:.0%})"
            )
            lines.append(
                f"   findings          {target.confirmed_count} confirmed, "
                f"{target.suspected_count} suspected"
            )
            for label in target.missed:
                lines.append(f"   MISSED            {label.key}")
                if label.note:
                    lines.append(f"                     {label.note}")
            for finding in target.false_positives:
                lines.append(
                    f"   FALSE POSITIVE    [{finding.confidence.value}] {finding.location} "
                    f"— {finding.category.value}"
                )
            for error in target.errors:
                lines.append(f"   note              {error}")

        lines.append("")
        lines.append("─" * 60)
        lines.append(
            f"   overall recall    {self.recall:.1%}  (floor {self.min_recall:.0%})"
            f"   false positives   {self.false_positives}"
        )
        lines.append("   " + ("PASS" if self.passed else "FAIL"))
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Label loading
# --------------------------------------------------------------------------- #


def load_labels(path: str | Path) -> dict[str, dict[str, Any]]:
    """Read the answer key."""
    document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or "targets" not in document:
        msg = f"{path} does not look like a labels file (no 'targets' key)"
        raise ValueError(msg)
    targets = document["targets"]
    if not isinstance(targets, dict):
        msg = f"{path}: 'targets' must be a mapping of target name to definition"
        raise ValueError(msg)
    return targets


def _labels_of(entry: dict[str, Any]) -> tuple[tuple[Label, ...], tuple[CleanLabel, ...]]:
    expected = tuple(
        Label(
            id=str(item.get("id", "?")),
            location=str(item["location"]),
            category=str(item["category"]),
            severity=str(item.get("severity", "")),
            engine=str(item.get("engine", "probe")),
            attack=item.get("attack"),
            note=str(item.get("note", "")),
        )
        for item in entry.get("expected", []) or []
    )
    clean = tuple(
        CleanLabel(location=str(item["location"]), reason=str(item.get("reason", "")))
        for item in entry.get("expect_clean", []) or []
    )
    return expected, clean


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


def _canonical(location: str, engine: str) -> str:
    """Normalise a location so a label and a finding compare equal."""
    if engine == "static" or "::" in location or location.endswith(".py"):
        return normalize_source_location(location)
    method, _, path = location.partition(" ")
    return f"{method.upper()} {normalize_path(path)}" if path else normalize_path(method)


def _matches(label: Label, finding: Finding) -> bool:
    if label.category != finding.category.value:
        return False
    engine = "static" if finding.engine is Engine.STATIC else "probe"
    if label.engine == "static" and engine != "static":
        return False
    return _canonical(label.location, label.engine) == _canonical(finding.location, engine)


def _is_clean_violation(clean: Sequence[CleanLabel], finding: Finding) -> bool:
    engine = "static" if finding.engine is Engine.STATIC else "probe"
    found = _canonical(finding.location, engine)
    return any(_canonical(c.location, "probe") == found for c in clean)


def score_findings(
    target: str,
    findings: Sequence[Finding],
    expected: Sequence[Label],
    clean: Sequence[CleanLabel],
) -> TargetScore:
    """Compare one target's findings against its labels."""
    result = TargetScore(target=target, expected=tuple(expected))
    result.confirmed_count = sum(1 for f in findings if f.confidence is Confidence.CONFIRMED)
    result.suspected_count = sum(1 for f in findings if f.confidence is Confidence.SUSPECTED)

    unclaimed = list(findings)
    for label in expected:
        hit = next((f for f in unclaimed if _matches(label, f)), None)
        if hit is None:
            result.missed.append(label)
        else:
            result.matched.append(label)
            unclaimed.remove(hit)

    for finding in findings:
        if _is_clean_violation(clean, finding):
            result.false_positives.append(finding)

    # Confirmed findings that match no label are false positives too: a
    # confirmed finding is a claim that a leak exists, and an unlabelled claim
    # against a fixture we wrote is a claim about a leak we did not build.
    for finding in unclaimed:
        if (
            finding.confidence is Confidence.CONFIRMED
            and finding.category.value != "harness_error"
            and finding not in result.false_positives
        ):
            result.false_positives.append(finding)

    return result


# --------------------------------------------------------------------------- #
# Running the engines against a fixture
# --------------------------------------------------------------------------- #


def _import_app(dotted: str) -> Any:
    """Import a fixture application with a clean in-memory database.

    Reloading rather than reusing the imported module matters: the fixture apps
    hold their database at module scope, so scoring the second target against
    the first one's leftover rows would make the aggregate oracle wrong.
    """
    ensure_cwd_importable()
    module_name, _, attr = dotted.partition(":")
    module = importlib.reload(importlib.import_module(module_name))
    app = getattr(module, attr, None)
    if app is None:
        msg = f"{module_name!r} has no attribute {attr!r}"
        raise ValueError(msg)
    return app


def audit_target(
    name: str,
    entry: dict[str, Any],
    *,
    config_path: str | Path,
    static_path: str | Path | None = None,
) -> tuple[list[Finding], RunStatus, ScopingMode, list[str]]:
    """Run both engines against one fixture application, in-process."""
    from tenanttrace.correlate.linker import correlate
    from tenanttrace.probe.asgi import SyncASGITransport
    from tenanttrace.probe.runner import ProbeOptions, run_probe

    config: Config = load_config(config_path)
    transport = SyncASGITransport(_import_app(str(entry["module"])))
    try:
        outcome = run_probe(
            config,
            ProbeOptions(
                allow_mutation=True,
                transport=transport,
                write_artifacts=False,
                redact=True,
            ),
        )
    finally:
        transport.close()
    errors = list(outcome.report.errors)

    static_findings: list[Finding] = []
    scoping = ScopingMode.UNKNOWN
    path = static_path or config.static.path
    if path:
        try:
            from tenanttrace.static.engine import scan

            result = scan(Path(path), config)
            static_findings = list(result.findings)
            scoping = result.scoping.mode
            errors.extend(result.warnings)
        except ImportError as exc:  # pragma: no cover - static engine optional at this stage
            errors.append(f"static engine unavailable: {exc}")

    merged = correlate(list(outcome.report.findings), static_findings)
    return list(merged.findings), outcome.report.status, scoping, errors


def score_targets(
    labels_path: str | Path,
    *,
    min_recall: float = 0.90,
    configs: dict[str, str] | None = None,
) -> MetricsReport:
    """Audit every labelled fixture and score the results."""
    targets = load_labels(labels_path)
    config_map = configs or {
        "vulnerable_app": "fixtures/tenanttrace.vulnerable.toml",
        "safe_app": "fixtures/tenanttrace.safe.toml",
    }

    report = MetricsReport(min_recall=min_recall)
    for name, entry in targets.items():
        expected, clean = _labels_of(entry)
        config_path = config_map.get(name)
        if config_path is None:
            score = TargetScore(target=name, expected=expected)
            score.errors.append("no audit configuration mapped for this target")
            report.targets.append(score)
            continue

        findings, status, scoping, errors = audit_target(name, entry, config_path=config_path)
        score = score_findings(name, findings, expected, clean)
        score.status = status
        score.scoping_detected = scoping
        score.scoping_expected = _mode(entry.get("scoping_mode"))
        score.errors = [e for e in errors if e]
        report.targets.append(score)

    return report


def _mode(value: Any) -> ScopingMode:
    if isinstance(value, str):
        try:
            return ScopingMode(value)
        except ValueError:
            return ScopingMode.UNKNOWN
    return ScopingMode.UNKNOWN


def iter_missed(report: MetricsReport) -> Iterable[Label]:
    """Every label no engine reported, across all targets."""
    for target in report.targets:
        yield from target.missed
