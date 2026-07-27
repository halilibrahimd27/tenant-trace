"""Command-line interface.

Exit codes are part of the contract, because this tool's main job is to be a
merge gate:

===  ==========================================================================
0    the run completed and nothing gated the build
1    confirmed findings at or above ``fail_on`` — the gate failed
2    usage or configuration error; nothing was probed
3    the run was **INVALID** — positive controls failed, so the result says
     nothing about the application. This is deliberately *not* 0: a broken
     harness must never be able to report a green build.
===  ==========================================================================
"""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from tenanttrace import __version__
from tenanttrace._importing import ensure_cwd_importable
from tenanttrace.core.config import Config, ConfigError, TargetConfig, load_config
from tenanttrace.core.models import (
    Confidence,
    Finding,
    RunReport,
    RunStatus,
    Severity,
    Verdict,
)
from tenanttrace.core.text import count

app = typer.Typer(
    name="tenanttrace",
    help="Prove whether tenant A can reach tenant B's data.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err = Console(stderr=True)


@app.callback()
def _main() -> None:
    """Prove whether tenant A can reach tenant B's data.

    Module paths in your configuration — the seeder adapter, a custom auth
    resolver — are resolved relative to the directory you run this from.
    """
    # An installed console script does not put the working directory on
    # sys.path the way `python -m` does. Without this, the seeder path the
    # documentation tells people to write would never import.
    ensure_cwd_importable()


EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INVALID = 3

ConfigOption = Annotated[Path, typer.Option("--config", "-c", help="Path to tenanttrace.toml")]


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def _load(
    config_path: Path,
    *,
    base_url: str | None = None,
    out_dir: Path | None = None,
    fail_on: str | None = None,
) -> Config:
    overrides: dict[str, dict[str, object]] = {}
    if base_url:
        overrides["target"] = {"base_url": base_url}
    report: dict[str, object] = {}
    if out_dir:
        report["out_dir"] = str(out_dir)
    if fail_on:
        report["fail_on"] = fail_on
    if report:
        overrides["report"] = report
    try:
        config = load_config(config_path, overrides=overrides or None)
    except ConfigError as exc:
        err.print(f"[bold red]configuration error[/]\n{escape(str(exc))}")
        raise typer.Exit(EXIT_USAGE) from exc
    if base_url:
        # A --base-url the operator typed still has to clear allowed_hosts.
        host = config.target.host
        if not config.target.host_allowed():
            err.print(
                f"[bold red]--base-url {base_url} resolves to host {host!r}, which is not "
                f"in the configured allowed_hosts.[/]"
            )
            raise typer.Exit(EXIT_USAGE)
    return config


def _print_findings(findings: list[Finding], *, title: str) -> None:
    if not findings:
        console.print(f"[green]{title}: none[/]")
        return
    table = Table(title=title, show_lines=False, header_style="bold")
    table.add_column("id", style="dim", no_wrap=True)
    table.add_column("severity", no_wrap=True)
    table.add_column("confidence", no_wrap=True)
    table.add_column("category", no_wrap=True)
    table.add_column("location", overflow="fold")
    for finding in findings:
        colour = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }[finding.severity]
        confidence_colour = "bold" if finding.confidence is Confidence.CONFIRMED else "dim"
        table.add_row(
            finding.id,
            f"[{colour}]{finding.severity.value}[/]",
            f"[{confidence_colour}]{finding.confidence.value}[/]",
            finding.category.value,
            finding.location,
        )
    console.print(table)


def _print_verdict(report: RunReport) -> None:
    """The outcome in one line, in the same words the HTML report uses.

    A table of findings answers "what", not "so what". This is the line that
    gets pasted into a chat window, so it has to hold up on its own — in
    particular it must never let "we refused everything" and "we tested
    nothing" print the same way.
    """
    if report.status is not RunStatus.VALID:
        return  # the INVALID banner already said it, louder.

    confirmed = len(report.confirmed)
    if confirmed:
        console.print(
            f"[bold red]✗ {count(confirmed, 'confirmed cross-tenant leak')}[/] — another "
            "tenant's data was returned. Each finding carries the request that proved it."
        )
        return
    enforced = sum(1 for r in report.results if r.verdict is Verdict.ENFORCED)
    undecided = sum(1 for r in report.results if r.verdict is Verdict.INCONCLUSIVE)
    if not enforced:
        err.print(
            "[bold yellow]! Nothing was proven either way[/] — not one cross-tenant "
            f"attempt was refused ({count(undecided, 'attempt')} could not be judged). "
            "This run is not evidence of isolation."
        )
        return
    trailer = f", {count(undecided, 'attempt')} undecided" if undecided else ""
    console.print(
        f"[green]✓ No cross-tenant access proven[/] — {count(enforced, 'attempt')} "
        f"refused across {count(report.endpoints_tested, 'endpoint')}{trailer}. "
        "Covers what was probed, not the whole application."
    )


def _print_status(report: RunReport) -> None:
    if report.status is RunStatus.VALID:
        console.print(
            f"[green]run VALID[/] — {report.endpoints_tested}/{report.endpoints_discovered} "
            f"endpoints probed, {len(report.results)} cross-tenant attempts"
        )
        return
    err.print(
        "[bold white on red] RUN INVALID [/] this audit did not happen, so it says NOTHING "
        "about tenant isolation.\nIt is not a clean result — it is an untested application. "
        "Fix the harness and run again."
    )
    for error in report.errors:
        err.print(f"  • {escape(error)}")


def _emit_reports(config: Config, report: RunReport, *, redact: bool) -> list[Path]:
    from tenanttrace.core.report import write_reports

    written = write_reports(
        report,
        config.out_path(),
        list(config.report.formats),
        redact=redact,
    )
    for path in written:
        console.print(f"  report → {path}")
    return list(written)


def _correlate_with_static(report: RunReport, config: Config, scan_path: Path | None) -> RunReport:
    """Merge static hypotheses into a probe report, when a source tree is known.

    This is what makes the correlated finding the README describes reachable
    from the command line: before, `probe` and `scan` were separate commands
    whose outputs never met, so `Engine.CORRELATED` could only be produced by
    calling the library directly.
    """
    path = scan_path or (Path(config.static.path) if config.static.path else None)
    if path is None:
        return report
    if not path.exists():
        err.print(f"[yellow]static path {path} does not exist — skipping the static pass[/]")
        return report

    from tenanttrace.correlate.linker import correlate
    from tenanttrace.static.engine import scan as scan_source

    try:
        result = scan_source(path, config)
    except Exception as exc:  # noqa: BLE001 - a static failure must not lose the probe run
        err.print(f"[yellow]static scan failed: {escape(f'{type(exc).__name__}: {exc}')}[/]")
        return report

    merged = correlate(list(report.findings), list(result.findings))
    console.print(
        f"  static: {count(result.files_scanned, 'file')}, scoping {result.scoping.mode.value}, "
        f"{len(result.findings)} hypothes(es), {len(merged.links)} correlated"
    )
    return report.model_copy(
        update={
            "findings": merged.findings,
            "scoping_mode": result.scoping.mode,
            "errors": (*report.errors, *result.warnings),
        }
    )


def _gate(config: Config, report: RunReport, baseline_path: Path | None) -> int:
    """Apply the baseline and the severity threshold; return an exit code."""
    from tenanttrace.core.baseline import gate as gate_findings
    from tenanttrace.core.baseline import load_baseline

    if report.status is not RunStatus.VALID:
        return EXIT_INVALID

    path = baseline_path or (Path(config.report.baseline) if config.report.baseline else None)
    baseline = load_baseline(path) if path else None
    decision = gate_findings(
        list(report.findings),
        fail_on=config.report.fail_threshold,
        baseline=baseline,
    )
    style = "red" if decision.failed else "green"
    console.print(f"[{style}]{escape(decision.message)}[/]")
    return EXIT_FINDINGS if decision.failed else EXIT_OK


# --------------------------------------------------------------------------- #
# probe
# --------------------------------------------------------------------------- #


@app.command()
def probe(
    config_path: ConfigOption = Path("tenanttrace.toml"),
    base_url: Annotated[
        str | None, typer.Option("--base-url", help="Override [target] base_url")
    ] = None,
    out_dir: Annotated[Path | None, typer.Option("--out", help="Override [report] out_dir")] = None,
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Override [report] fail_on: critical|high|medium|low|none"),
    ] = None,
    allow_mutation: Annotated[
        bool,
        typer.Option("--allow-mutation", help="Enable attacks that WRITE to the target"),
    ] = False,
    i_have_authorization: Annotated[
        bool,
        typer.Option(
            "--i-have-authorization",
            help="Required for non-loopback targets. A statement you are making.",
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="List what would be attempted. Sends no attack traffic (it does\n"
            "fetch the API description).",
        ),
    ] = False,
    full_evidence: Annotated[
        bool,
        typer.Option("--full-evidence", help="Do not redact evidence in reports (careful)"),
    ] = False,
    baseline: Annotated[
        Path | None, typer.Option("--baseline", help="Baseline file of accepted findings")
    ] = None,
    scan_path: Annotated[
        Path | None,
        typer.Option("--scan", help="Source tree to analyse; defaults to [static] path"),
    ] = None,
    no_correlate: Annotated[
        bool, typer.Option("--no-correlate", help="Skip the static pass entirely")
    ] = False,
    no_report: Annotated[
        bool, typer.Option("--no-report", help="Skip writing rendered reports")
    ] = False,
) -> None:
    """Run the dynamic prober against a target.

    When a source tree is configured, the static engine runs too and its
    hypotheses are correlated with the confirmed leaks — so one report carries
    both the endpoint that leaked and the line responsible. Static findings
    stay `suspected` and never gate the build (rule 3).
    """
    from tenanttrace.probe.runner import ProbeOptions, run_probe

    config = _load(config_path, base_url=base_url, out_dir=out_dir, fail_on=fail_on)
    redact = config.report.redact_evidence and not full_evidence

    try:
        outcome = run_probe(
            config,
            ProbeOptions(
                allow_mutation=allow_mutation,
                i_have_authorization=i_have_authorization,
                dry_run=dry_run,
                redact=redact,
            ),
        )
    except ConfigError as exc:
        err.print(f"[bold red]refused to probe[/]\n{escape(str(exc))}")
        raise typer.Exit(EXIT_USAGE) from exc

    if dry_run:
        console.print(f"[bold]dry run[/] — {count(len(outcome.plan), 'attempt')} would be made:\n")
        for line in outcome.plan:
            console.print(f"  {line}")
        raise typer.Exit(EXIT_OK)

    report = outcome.report
    if not no_correlate:
        report = _correlate_with_static(report, config, scan_path)

    _print_status(report)
    _print_findings(list(report.ranked()), title="Findings")
    _print_verdict(report)
    if outcome.artifact_dir:
        console.print(f"  artifacts → {outcome.artifact_dir}")
    if not no_report:
        _emit_reports(config, report, redact=redact)

    raise typer.Exit(_gate(config, report, baseline))


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #


@app.command()
def scan(
    path: Annotated[Path, typer.Option("--path", "-p", help="Source tree to analyse")],
    config_path: ConfigOption = Path("tenanttrace.toml"),
) -> None:
    """Run the static engine. Everything it reports is a hypothesis.

    Static findings are `suspected` and never fail a build on their own — the
    prober has to confirm them first (see ADR-0002).
    """
    from tenanttrace.static.engine import scan as scan_path

    try:
        config = load_config(config_path)
    except ConfigError:
        # A static scan needs no target, so a missing config is not fatal here:
        # pointing the analyser at a repository should not require first
        # describing a running application.
        config = Config(target=TargetConfig(base_url="http://127.0.0.1"))

    result = scan_path(path, config)
    console.print(
        f"scanned {count(result.files_scanned, 'file')}; scoping mode detected: "
        f"[bold]{result.scoping.mode.value}[/]"
    )
    for reason in result.scoping.reasons[:5]:
        console.print(f"  • {reason}")
    for warning in result.warnings[:10]:
        err.print(f"  [yellow]warning[/] {escape(warning)}")
    _print_findings(sorted(result.findings, key=lambda f: f.sort_key), title="Hypotheses")
    console.print(
        "\n[dim]These are hypotheses, not verdicts. Run `tenanttrace probe` to confirm "
        "them before acting.[/]"
    )


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #


@app.command()
def report(
    run: Annotated[
        Path | None,
        typer.Option("--run", help="Run directory or report.json (default: latest)"),
    ] = None,
    config_path: ConfigOption = Path("tenanttrace.toml"),
    fmt: Annotated[str, typer.Option("--format", "-f", help="json | md | html")] = "md",
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Write to a file")] = None,
    full_evidence: Annotated[bool, typer.Option("--full-evidence")] = False,
) -> None:
    """Re-render a stored run in another format."""
    from tenanttrace.core.report import read_report, render

    config = _load(config_path) if config_path.exists() else None
    source = _resolve_run(run, config)
    if source is None:
        err.print("[bold red]no run found.[/] Run `tenanttrace probe` first.")
        raise typer.Exit(EXIT_USAGE)

    rendered = render(read_report(source), fmt, redact=not full_evidence)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        console.print(f"report → {out}")
    else:
        sys.stdout.write(rendered)


def _resolve_run(run: Path | None, config: Config | None) -> Path | None:
    """Find the report.json to render."""
    if run is not None:
        if run.is_dir():
            candidate = run / "report.json"
            return candidate if candidate.is_file() else None
        return run if run.is_file() else None

    root = (config.out_path() if config else Path(".tenanttrace")) / "runs"
    if not root.is_dir():
        return None
    runs = sorted((p for p in root.iterdir() if p.is_dir()), reverse=True)
    for candidate in runs:
        report_file = candidate / "report.json"
        if report_file.is_file():
            return report_file
    return None


# --------------------------------------------------------------------------- #
# metrics
# --------------------------------------------------------------------------- #


@app.command()
def summary(
    run: Annotated[
        Path | None, typer.Option("--run", help="Run directory or report.json (default: latest)")
    ] = None,
    config_path: ConfigOption = Path("tenanttrace.toml"),
) -> None:
    """Print a summary safe to publish in a public CI log or PR comment.

    Deliberately not the full report. A job summary and a pull-request comment
    on a public repository are readable by anyone, and the full report contains
    response bodies — which, on a real target, are another tenant's data. This
    prints counts, categories, locations, and status: enough to act on, and not
    enough to hand a passer-by a working exploit with the data attached.
    """
    from tenanttrace.core.report import read_report

    config = _load(config_path) if config_path.exists() else None
    source = _resolve_run(run, config)
    if source is None:
        err.print("[bold red]no run found.[/] Run `tenanttrace probe` first.")
        raise typer.Exit(EXIT_USAGE)

    stored = read_report(source)
    lines = ["### TenantTrace — tenant isolation audit", ""]

    if stored.status is not RunStatus.VALID:
        reason = next(
            (f.evidence.note for f in stored.findings if f.evidence.note),
            "the run could not be completed",
        )
        lines += [
            f"> **RUN INVALID.** {reason}",
            ">",
            "> Nothing below is evidence of isolation. An empty finding list here does",
            "> not mean the application is clean; it means it was never tested.",
            "",
        ]

    confirmed = list(stored.confirmed)
    counts: dict[str, int] = {}
    for finding in confirmed:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    histogram = " · ".join(f"**{counts[s]}** {s}" for s in order if counts.get(s))

    headline = count(len(confirmed), "confirmed finding")
    lines.append(headline + (f": {histogram}" if histogram else ""))
    lines.append(
        f"Coverage: {stored.endpoints_tested} of {stored.endpoints_discovered} known "
        f"endpoints, {len(stored.results)} cross-tenant attempts."
    )

    if confirmed:
        lines += ["", "| severity | category | location |", "| --- | --- | --- |"]
        lines += [
            f"| {f.severity.value} | {f.category.value} | `{f.location}` |" for f in confirmed
        ]

    suspected = list(stored.suspected)
    if suspected:
        lines += [
            "",
            f"{len(suspected)} static hypothes(es) reported; they do not gate this build.",
        ]
    if stored.errors:
        lines += ["", "<details><summary>Run notes</summary>", ""]
        lines += [f"- {e}" for e in stored.errors]
        lines += ["", "</details>"]

    lines += [
        "",
        "<sub>Evidence, response bodies and canary values are in the run artifact, "
        "not here.</sub>",
    ]
    sys.stdout.write("\n".join(lines) + "\n")


@app.command()
def metrics(
    labels: Annotated[Path, typer.Option("--labels", help="Answer key")] = Path(
        "fixtures/labels.yaml"
    ),
    min_recall: Annotated[
        float, typer.Option("--min-recall", help="Recall floor; below this the gate fails")
    ] = 0.90,
) -> None:
    """Score the tool against the labelled fixtures. This is the quality gate."""
    from tenanttrace.metrics import score_targets

    if not labels.is_file():
        err.print(f"[bold red]labels file not found:[/] {labels}")
        raise typer.Exit(EXIT_USAGE)

    report_ = score_targets(labels, min_recall=min_recall)
    # markup=False: this block is plain text that legitimately contains square
    # brackets — "[probe] exclude_paths", "[confirmed] GET /x". Rich would read
    # those as style tags and silently delete them, so the one line explaining
    # why an endpoint was skipped would lose the name of the setting to change.
    console.print(report_.render(), markup=False, highlight=False)
    raise typer.Exit(EXIT_OK if report_.passed else EXIT_FINDINGS)


# --------------------------------------------------------------------------- #
# demo
# --------------------------------------------------------------------------- #


@app.command()
def demo(
    which: Annotated[str, typer.Option("--app", help="vulnerable | safe | both")] = "both",
    out_dir: Annotated[Path, typer.Option("--out", help="Where to write the demo reports")] = Path(
        ".tenanttrace/demo"
    ),
    fmt: Annotated[str, typer.Option("--format", "-f", help="json | md | html")] = "html",
) -> None:
    """Audit the bundled fixture applications end to end, with no server.

    This is the fastest way to see what a real report looks like: it seeds two
    tenants into the deliberately-vulnerable app, proves the leaks, and writes
    the same report you would get against your own application.
    """
    from tenanttrace.core.report import render
    from tenanttrace.probe.asgi import SyncASGITransport
    from tenanttrace.probe.runner import ProbeOptions, run_probe

    targets = {
        "vulnerable": ("fixtures.vulnerable_app.main:app", "fixtures/tenanttrace.vulnerable.toml"),
        "safe": ("fixtures.safe_app.main:app", "fixtures/tenanttrace.safe.toml"),
    }
    chosen = list(targets) if which == "both" else [which]
    for name in chosen:
        if name not in targets:
            err.print(f"[bold red]unknown app {name!r}[/] — choose vulnerable, safe, or both")
            raise typer.Exit(EXIT_USAGE)

    out_dir.mkdir(parents=True, exist_ok=True)
    failed = False

    for name in chosen:
        dotted, config_file = targets[name]
        module_name, _, attr = dotted.partition(":")
        application = getattr(importlib.import_module(module_name), attr)
        config = load_config(config_file)

        console.rule(f"[bold]{name}_app")
        transport = SyncASGITransport(application)
        try:
            outcome = run_probe(
                config,
                ProbeOptions(
                    allow_mutation=True,
                    transport=transport,
                    write_artifacts=False,
                ),
            )
        finally:
            transport.close()

        _print_status(outcome.report)
        _print_findings(list(outcome.report.ranked()), title=f"{name}_app findings")
        _print_verdict(outcome.report)

        target_file = out_dir / f"{name}_app.{ 'md' if fmt == 'md' else fmt }"
        target_file.write_text(render(outcome.report, fmt), encoding="utf-8")
        console.print(f"  report → {target_file}")

        if name == "vulnerable" and not outcome.report.confirmed:
            err.print("[bold red]the vulnerable fixture reported no leaks — that is a bug[/]")
            failed = True
        if name == "safe" and outcome.report.confirmed:
            err.print("[bold red]the safe fixture reported a leak — that is a false positive[/]")
            failed = True

    raise typer.Exit(EXIT_FINDINGS if failed else EXIT_OK)


# --------------------------------------------------------------------------- #
# validate-config / version
# --------------------------------------------------------------------------- #


@app.command()
def init(
    config_path: ConfigOption = Path("tenanttrace.toml"),
    seeder_path: Annotated[
        Path, typer.Option("--seeder", help="Where to write the seeder stub")
    ] = Path("seeders/my_app.py"),
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing files")] = False,
) -> None:
    """Scaffold a config and a seeder stub for your own application.

    Two files and nothing else. The seeder is the only code you have to write,
    and the stub marks the four methods that need filling in.
    """
    template = _example_config_path()
    module = str(seeder_path.with_suffix("")).replace("/", ".").replace("\\", ".")
    written: list[Path] = []

    for path, content in (
        (config_path, _config_template(template, module)),
        (seeder_path, _SEEDER_STUB),
    ):
        if path.exists() and not force:
            err.print(f"[yellow]{path} already exists — leaving it alone (use --force)[/]")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        written.append(path)

    for path in written:
        console.print(f"  wrote {path}")
    if written:
        module = str(seeder_path.with_suffix("")).replace("/", ".").replace("\\", ".")
        console.print(
            f"\nNext: fill in the four methods in [bold]{seeder_path}[/], point "
            f"[bold]{config_path}[/] at your app, then:\n\n"
            f"  tenanttrace validate-config -c {config_path}\n"
            f"  tenanttrace probe -c {config_path} --dry-run\n\n"
            # Escaped: rich reads square brackets as markup, and a TOML
            # section name is exactly that shape.
            f"[dim]The config's \\[seeder] adapter should read "
            f'"{module}:MySeeder".[/]'
        )


def _example_config_path() -> Path:
    """Locate the documented example config, installed or in a checkout."""
    here = Path(__file__).resolve().parent
    candidates = (
        here / "data" / "tenanttrace.example.toml",  # installed wheel
        here.parents[1] / "tenanttrace.example.toml",  # editable install / checkout
    )
    return next((c for c in candidates if c.is_file()), candidates[0])


def _config_template(example: Path, seeder_module: str) -> str:
    """The shipped example, pointed at the seeder this command just wrote.

    A scaffold whose config names a seeder that does not exist in the user's
    project would fail on their first run, which is a poor introduction.
    """
    adapter_line = f'adapter = "{seeder_module}:MySeeder"'
    if example.is_file():
        text = example.read_text(encoding="utf-8")
        return re.sub(r'^adapter = "[^"]*"$', adapter_line, text, count=1, flags=re.MULTILINE)
    return (
        "[target]\n"
        'base_url = "http://127.0.0.1:8000"\n'
        'allowed_hosts = ["127.0.0.1", "localhost"]\n\n'
        f"[seeder]\n{adapter_line}\n\n"
        "[tenancy]\n"
        'column = "tenant_id"\n'
        "cross_tenant_allowlist = []\n\n"
        "[report]\n"
        'fail_on = "high"\n'
    )


_SEEDER_STUB = '''"""Seeder adapter — the one file you write per application.

TenantTrace needs three things it cannot guess: how to create a tenant, how to
authenticate as one, and how to create a record that carries a canary. Fill
these in and everything else works.

Two rules worth knowing before you start:

* The canary must land in a field your API actually returns. A canary stored
  somewhere no response includes cannot prove anything.
* Create at least two records per kind. The harness keeps its control reads and
  its attack reads on different records, which is what stops a tenant-less
  cache from being misreported as a missing query filter.
"""

from __future__ import annotations

from typing import Any

import httpx


class MySeeder:
    def __init__(self, client: httpx.Client, **_: Any) -> None:
        self.client = client
        self._tokens: dict[str, str] = {}

    def create_tenant(self, label: str) -> dict[str, Any]:
        """Create a tenant. Return whatever identifies it downstream."""
        response = self.client.post("/api/signup", json={"company": f"tenanttrace-{label}"})
        response.raise_for_status()
        payload = response.json()
        self._tokens[payload["tenant_id"]] = payload["access_token"]
        return {"tenant_id": payload["tenant_id"], "access_token": payload["access_token"]}

    def auth_headers(self, tenant: dict[str, Any]) -> dict[str, str]:
        """Headers that authenticate a request as this tenant."""
        return {"Authorization": f"Bearer {tenant['access_token']}"}

    def seed_records(self, tenant: dict[str, Any], canary: str) -> list[dict[str, Any]]:
        """Create records carrying the canary. Return them with `kind` and `id`."""
        headers = self.auth_headers(tenant)
        records: list[dict[str, Any]] = []
        for index in range(2):
            response = self.client.post(
                "/api/invoices",
                headers=headers,
                json={"title": f"{canary} invoice {index}", "amount": 100 + index},
            )
            response.raise_for_status()
            records.append({**response.json(), "kind": "invoice"})
        return records

    def cleanup(self, tenant: dict[str, Any]) -> None:
        """Remove what this run created. Called even when the run fails.

        `tenant` carries no credentials on purpose, so look up your own token
        as this stub does rather than expecting one to be handed back.
        """
        token = self._tokens.get(str(tenant.get("tenant_id", "")))
        if not token:
            return
        # e.g. self.client.delete(f"/api/tenants/{tenant['tenant_id']}",
        #                         headers={"Authorization": f"Bearer {token}"})
'''


@app.command("validate-config")
def validate_config(config_path: ConfigOption = Path("tenanttrace.toml")) -> None:
    """Parse a config file and report exactly what it will do."""
    config = _load(config_path)
    console.print(f"[green]{config_path} is valid.[/]\n")
    table = Table(show_header=False, box=None)
    table.add_row("target", config.target.base_url)
    table.add_row("loopback", "yes" if config.target.is_loopback else "NO — needs authorization")
    table.add_row("allowed hosts", ", ".join(config.target.allowed_hosts))
    table.add_row("spec", f"{config.target.spec} @ {config.target.spec_path or '(default)'}")
    table.add_row("seeder", config.seeder.adapter or "(none — required for probing)")
    table.add_row("tenant column", config.tenancy.column)
    table.add_row("scoping mode", config.tenancy.scoping_mode)
    table.add_row("attacks", ", ".join(a.value for a in config.probe.attacks))
    mutation = "yes (still needs --allow-mutation)" if config.probe.allow_mutation else "no"
    table.add_row("mutation allowed", mutation)
    table.add_row("allowlist", ", ".join(config.tenancy.cross_tenant_allowlist) or "(none)")
    table.add_row("fail_on", config.report.fail_on)
    console.print(table)


@app.command()
def version() -> None:
    """Print the version."""
    console.print(f"tenanttrace {__version__}")


def main() -> None:  # pragma: no cover - console-script entry point
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
