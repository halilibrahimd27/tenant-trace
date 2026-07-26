"""Rendering a run into something a person acts on.

Three formats, three audiences: JSON for a machine, Markdown for a pull request
or a pentest report, HTML for the person who opened the link.

Two rules cut across all of them.

**The run's status is the first thing on the page.** A report from an INVALID
run opens with a block saying so, because the difference between "we found
nothing" and "we could not test anything" is the entire difference between a
security tool and a placebo — and it is invisible in a finding count.

**Everything that came from the target is hostile text.** Response snippets are
attacker-influenced by construction; in HTML they are escaped, and no format
ever renders a credential.
"""

from __future__ import annotations

import html
import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from tenanttrace.core.models import (
    CANARY_RE,
    Confidence,
    ControlResult,
    Evidence,
    Finding,
    ProbeResult,
    RunReport,
    RunStatus,
    Severity,
    Verdict,
)
from tenanttrace.core.redaction import redact_headers as _redact_headers

__all__ = [
    "SCHEMA_VERSION",
    "read_report",
    "redact_evidence",
    "render",
    "render_html",
    "render_json",
    "render_markdown",
    "write_reports",
]

SCHEMA_VERSION = 1

# Long enough to prove a leak, short enough that a report stays readable.
SNIPPET_LIMIT = 500


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


def _mask_canary(canary: str | None) -> str | None:
    """Show a canary as its tail only.

    Enough to correlate two mentions of the same canary within one report;
    not enough to reproduce a seeded value from a screenshot or a public log.
    """
    if not canary:
        return None
    return f"tt-canary-…{canary[-8:]}" if len(canary) > 8 else canary


def _mask_canaries_in(text: str | None) -> str | None:
    """Shorten every canary occurrence inside a body.

    Masking only the ``matched_canary`` field while the same value sits
    verbatim three lines below it in the response snippet would make the
    redaction claim false. It is applied to the body too so the claim holds.
    """
    if not text:
        return text
    return CANARY_RE.sub(lambda m: f"tt-canary-…{m.group(0)[-8:]}", text)


def _strip_credentials(headers: Mapping[str, str]) -> dict[str, str]:
    """Remove credential header values. Not optional, in any mode.

    ``--full-evidence`` widens what a report shows about the *target's*
    responses. It is not a switch for printing our own tokens — there is no
    reason anybody would want that, and one accidental `--full-evidence` in CI
    would put a live credential in a build log.
    """
    return _redact_headers(headers)


def redact_evidence(evidence: Evidence, *, redact: bool = True) -> Evidence:
    """Return evidence safe to render.

    Note what this does *not* do: the response snippet still contains data the
    target returned, because that is the evidence. Truncation bounds it,
    credentials are removed, and canaries are shortened — but on a real target
    a rendered report contains real tenant data and should be handled as such.
    """
    if not redact:
        # Credentials are removed even here — see _strip_credentials.
        return evidence.model_copy(
            update={"request_headers": _strip_credentials(evidence.request_headers)}
        )
    snippet = evidence.response_snippet
    if snippet and len(snippet) > SNIPPET_LIMIT:
        snippet = snippet[:SNIPPET_LIMIT] + f"… [{len(snippet) - SNIPPET_LIMIT} more characters]"
    return evidence.model_copy(
        update={
            "request_headers": _strip_credentials(evidence.request_headers),
            "response_snippet": _mask_canaries_in(snippet),
            "request_body": _mask_canaries_in(evidence.request_body),
            "matched_canary": _mask_canary(evidence.matched_canary),
        }
    )


def _redacted_report(report: RunReport, *, redact: bool) -> RunReport:
    return report.model_copy(
        update={
            "findings": tuple(
                f.model_copy(update={"evidence": redact_evidence(f.evidence, redact=redact)})
                for f in report.findings
            ),
            "results": tuple(
                r.model_copy(update={"evidence": redact_evidence(r.evidence, redact=redact)})
                for r in report.results
            ),
            "controls": tuple(
                c.model_copy(update={"evidence": redact_evidence(c.evidence, redact=redact)})
                for c in report.controls
            ),
        }
    )


# --------------------------------------------------------------------------- #
# Shared summary helpers
# --------------------------------------------------------------------------- #

_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def _matrix(findings: Sequence[Finding]) -> dict[Severity, dict[Confidence, int]]:
    grid: dict[Severity, dict[Confidence, int]] = {
        severity: dict.fromkeys(Confidence, 0) for severity in _SEVERITY_ORDER
    }
    for finding in findings:
        grid[finding.severity][finding.confidence] += 1
    return grid


def _enforced(report: RunReport) -> list[ProbeResult]:
    return [r for r in report.results if r.verdict is Verdict.ENFORCED]


def _duration_seconds(report: RunReport) -> float | None:
    if report.finished_at is None:
        return None
    return (report.finished_at - report.started_at).total_seconds()


INVALID_HEADLINE = "RUN INVALID — the positive controls failed"
INVALID_BODY = (
    "A tenant could not read its own seeded data, so authentication or seeding is "
    "broken. Nothing in this report is evidence about tenant isolation. In "
    "particular, an empty finding list here does NOT mean the application is "
    "clean — it means the application was never successfully tested. Fix the "
    "harness and run again."
)


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def render_json(report: RunReport, *, redact: bool = True) -> str:
    """Machine-readable output, with stable key order."""
    prepared = _redacted_report(report, redact=redact)
    payload: dict[str, Any] = json.loads(prepared.model_dump_json())
    payload["schema_version"] = SCHEMA_VERSION
    payload["summary"] = {
        "status": prepared.status.value,
        "controls_passed": prepared.controls_passed,
        "confirmed": len(prepared.confirmed),
        "suspected": len(prepared.suspected),
        "attempts": len(prepared.results),
        "enforced": len(_enforced(prepared)),
        "endpoints_tested": prepared.endpoints_tested,
        "endpoints_discovered": prepared.endpoints_discovered,
        "duration_seconds": _duration_seconds(prepared),
        "by_severity": {
            severity.value: sum(counts.values())
            for severity, counts in _matrix(prepared.findings).items()
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #


def render_markdown(report: RunReport, *, redact: bool = True) -> str:
    """Drop-in pasteable into a pull request or a pentest report."""
    prepared = _redacted_report(report, redact=redact)
    out: list[str] = ["# TenantTrace — tenant isolation audit", ""]

    if prepared.status is not RunStatus.VALID:
        out += [
            f"> ## ⚠ {INVALID_HEADLINE}",
            ">",
            *[f"> {line}" for line in _wrap(INVALID_BODY)],
            "",
        ]
        for error in prepared.errors:
            out.append(f"> - {error}")
        out.append("")

    out += [
        f"**Target** `{prepared.target}` · **status** `{prepared.status.value.upper()}` · "
        f"**tool** tenanttrace {prepared.tool_version}",
        "",
        f"Started {prepared.started_at.isoformat()}"
        + (f", took {_duration_seconds(prepared):.1f}s" if _duration_seconds(prepared) else ""),
        "",
    ]

    # ---- controls -------------------------------------------------------
    out += ["## Positive controls", ""]
    if not prepared.controls:
        out.append("_No controls were run._")
    for control in prepared.controls:
        mark = "✅" if control.passed else "❌"
        out.append(f"- {mark} **{control.name}** — {control.detail}")
    out.append("")

    # ---- summary --------------------------------------------------------
    out += ["## Summary", ""]
    grid = _matrix(prepared.findings)
    out += [
        "| severity | confirmed | suspected | inconclusive |",
        "| --- | ---: | ---: | ---: |",
    ]
    for severity in _SEVERITY_ORDER:
        counts = grid[severity]
        if not sum(counts.values()):
            continue
        out.append(
            f"| {severity.value} | {counts[Confidence.CONFIRMED]} | "
            f"{counts[Confidence.SUSPECTED]} | {counts[Confidence.INCONCLUSIVE]} |"
        )
    if not prepared.findings:
        out.append("| _none_ | 0 | 0 | 0 |")
    out += [
        "",
        f"{len(prepared.confirmed)} confirmed, {len(prepared.suspected)} suspected across "
        f"{prepared.endpoints_tested} of {prepared.endpoints_discovered} known endpoints "
        f"({len(prepared.results)} cross-tenant attempts).",
        "",
    ]

    # ---- findings -------------------------------------------------------
    out += ["## Findings", ""]
    if not prepared.findings:
        out += ["_No findings._", ""]
    for finding in prepared.ranked():
        out += _markdown_card(finding)

    # ---- coverage -------------------------------------------------------
    out += _markdown_coverage(prepared)
    return "\n".join(out).rstrip() + "\n"


def _markdown_card(finding: Finding) -> list[str]:
    evidence = finding.evidence
    out = [
        f"### {finding.id} · {finding.title}",
        "",
        f"`{finding.severity.value}` · `{finding.confidence.value}` · "
        f"`{finding.engine.value}` · {' · '.join(finding.tags) if finding.tags else '—'}",
        "",
        f"**Location** `{finding.location}`",
        "",
    ]

    rows: list[tuple[str, str]] = []
    if evidence.request_line:
        rows.append(("Request", f"`{evidence.request_line}`"))
    if evidence.request_body:
        rows.append(("Request body", f"`{_oneline(evidence.request_body)}`"))
    if evidence.response_status is not None:
        rows.append(("Response", f"`{evidence.response_status}`"))
    if evidence.matched_canary:
        rows.append(("Canary that proved it", f"`{evidence.matched_canary}`"))
    if evidence.matched_ids:
        rows.append(("Leaked identifiers", ", ".join(f"`{i}`" for i in evidence.matched_ids[:5])))
    if evidence.expected_count is not None:
        rows.append(("Expected", f"`{evidence.expected_count}`"))
    if evidence.observed_count is not None:
        rows.append(("Observed", f"`{evidence.observed_count}`"))
    if evidence.file:
        location = f"`{evidence.file}`" + (f" line {evidence.line}" if evidence.line else "")
        rows.append(("Source", location))
    if evidence.note:
        rows.append(("Detail", evidence.note))
    if evidence.assumption:
        rows.append(("Assumption", evidence.assumption))
    if finding.related:
        rows.append(("Related", ", ".join(f"`{r}`" for r in finding.related)))

    if rows:
        out += ["| | |", "| --- | --- |"]
        out += [f"| {label} | {value} |" for label, value in rows]
        out.append("")

    if evidence.response_snippet:
        out += [
            "<details><summary>Response body</summary>",
            "",
            "```",
            evidence.response_snippet,
            "```",
            "",
            "</details>",
            "",
        ]
    if evidence.snippet:
        out += ["```python", evidence.snippet, "```", ""]

    if finding.remediation:
        out += ["**Remediation**", "", finding.remediation, ""]
    out.append("---")
    out.append("")
    return out


def _markdown_coverage(report: RunReport) -> list[str]:
    """What was checked and held.

    A report with zero findings and zero attempts and one with zero findings
    over four hundred attempts have the same headline number and are not the
    same document. This section is what tells them apart.
    """
    enforced = _enforced(report)
    out = ["## What was checked and held", ""]
    if not enforced:
        out += [
            "_No cross-tenant attempt was refused — which, with no findings either, "
            "means the run had no real coverage._",
            "",
        ]
        return out

    by_attack: dict[str, int] = {}
    for result in enforced:
        by_attack[result.attack.value] = by_attack.get(result.attack.value, 0) + 1
    out += [
        f"{len(enforced)} cross-tenant attempt(s) were correctly refused:",
        "",
        "| attack | refused |",
        "| --- | ---: |",
    ]
    out += [f"| {name} | {count} |" for name, count in sorted(by_attack.items())]

    inconclusive = [r for r in report.results if r.verdict is Verdict.INCONCLUSIVE]
    if inconclusive:
        out += [
            "",
            f"{len(inconclusive)} attempt(s) were **inconclusive** — the oracle could not "
            "decide, which is not the same as enforcement:",
            "",
        ]
        out += [f"- `{r.endpoint.key}` ({r.attack.value}) — {r.detail}" for r in inconclusive[:10]]
    if report.errors:
        out += ["", "**Run notes**", ""]
        out += [f"- {error}" for error in report.errors]
    out.append("")
    return out


def _oneline(text: str, limit: int = 200) -> str:
    collapsed = " ".join(text.split())
    return collapsed[:limit] + ("…" if len(collapsed) > limit else "")


def _wrap(text: str, width: int = 76) -> list[str]:
    import textwrap

    return textwrap.wrap(text, width=width)


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

_CSS = """
:root {
  color-scheme: light dark;
  --bg: #ffffff; --fg: #16181d; --muted: #5f6673; --line: #e3e6ea;
  --card: #ffffff; --code: #f5f6f8;
  --critical: #b3261e; --high: #c2410c; --medium: #a16207;
  --low: #0e7490; --info: #64748b; --ok: #15803d;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1115; --fg: #e6e8ec; --muted: #9aa1ad; --line: #262a33;
    --card: #161920; --code: #1c2027;
    --critical: #ff6b5e; --high: #fb923c; --medium: #fbbf24;
    --low: #38bdf8; --info: #94a3b8; --ok: #4ade80;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.65 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
}
.wrap { max-width: 60rem; margin: 0 auto; padding: 3rem 1.5rem 6rem; }
h1 { font-size: 1.75rem; margin: 0 0 .35rem; letter-spacing: -.02em; }
h2 { font-size: 1.1rem; margin: 2.75rem 0 .9rem; letter-spacing: -.01em; }
h3 { font-size: 1rem; margin: 0 0 .5rem; }
p.meta { color: var(--muted); margin: 0 0 2rem; font-size: .9rem; }
code, pre { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace; }
code { background: var(--code); padding: .1rem .35rem; border-radius: .3rem; font-size: .875em; }
pre {
  background: var(--code); padding: .9rem 1rem; border-radius: .5rem;
  overflow-x: auto; font-size: .8rem; line-height: 1.5; margin: .6rem 0;
}
pre code { background: none; padding: 0; font-size: inherit; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { text-align: left; padding: .45rem .7rem; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; font-size: .78rem;
     text-transform: uppercase; letter-spacing: .04em; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.scroll { overflow-x: auto; }
.invalid {
  border: 1px solid var(--critical); border-left-width: 4px; border-radius: .6rem;
  padding: 1.1rem 1.3rem; margin: 0 0 2rem;
  background: color-mix(in srgb, var(--critical) 8%, transparent);
}
.invalid h2 { margin: 0 0 .5rem; color: var(--critical); font-size: 1.05rem; }
.invalid p { margin: 0 0 .5rem; }
.card {
  border: 1px solid var(--line); border-radius: .7rem; padding: 1.2rem 1.4rem;
  margin: 0 0 1.1rem; background: var(--card); border-left: 4px solid var(--info);
}
.card.critical { border-left-color: var(--critical); }
.card.high     { border-left-color: var(--high); }
.card.medium   { border-left-color: var(--medium); }
.card.low      { border-left-color: var(--low); }
.badges { display: flex; flex-wrap: wrap; gap: .4rem; margin: 0 0 .9rem; }
.badge {
  font-size: .7rem; font-weight: 650; text-transform: uppercase; letter-spacing: .05em;
  padding: .18rem .5rem; border-radius: .3rem; border: 1px solid var(--line);
  color: var(--muted); white-space: nowrap;
}
.badge.sev-critical { color: var(--critical); border-color: var(--critical); }
.badge.sev-high     { color: var(--high); border-color: var(--high); }
.badge.sev-medium   { color: var(--medium); border-color: var(--medium); }
.badge.sev-low      { color: var(--low); border-color: var(--low); }
.badge.confirmed    { color: var(--critical); border-color: var(--critical); }
.badge.suspected    { color: var(--medium); border-color: var(--medium); }
dl.kv { display: grid; grid-template-columns: minmax(7rem, max-content) 1fr;
        gap: .3rem .9rem; margin: 0 0 .9rem; font-size: .88rem; }
dl.kv dt { color: var(--muted); }
dl.kv dd { margin: 0; overflow-wrap: anywhere; }
details { margin: .6rem 0; }
summary { cursor: pointer; color: var(--muted); font-size: .85rem; }
.controls li { list-style: none; }
.controls { padding: 0; margin: 0 0 1rem; }
.pass { color: var(--ok); } .fail { color: var(--critical); }
.empty { color: var(--muted); font-style: italic; }
footer { margin-top: 4rem; padding-top: 1.2rem; border-top: 1px solid var(--line);
         color: var(--muted); font-size: .8rem; }
"""


def _e(value: object) -> str:
    """Escape anything before it reaches the page.

    Response snippets are strings the target chose. Without this, an
    application could inject markup into the report that describes its own
    vulnerability.
    """
    return html.escape(str(value), quote=True)


def render_html(report: RunReport, *, redact: bool = True) -> str:
    """A single self-contained page. No CDN, no fonts, no outbound requests."""
    prepared = _redacted_report(report, redact=redact)
    status = prepared.status.value.upper()
    parts: list[str] = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>TenantTrace — {_e(prepared.target)} [{_e(status)}]</title>",
        f"<style>{_CSS}</style>",
        "</head><body><div class='wrap'>",
        "<h1>TenantTrace — tenant isolation audit</h1>",
        f"<p class='meta'>{_e(prepared.target)} · run <strong>{_e(status)}</strong> · "
        f"tenanttrace {_e(prepared.tool_version)} · {_e(prepared.started_at.isoformat())}</p>",
    ]

    if prepared.status is not RunStatus.VALID:
        parts += [
            "<div class='invalid'>",
            f"<h2>⚠ {_e(INVALID_HEADLINE)}</h2>",
            f"<p>{_e(INVALID_BODY)}</p>",
            "<ul>" + "".join(f"<li>{_e(err)}</li>" for err in prepared.errors) + "</ul>",
            "</div>",
        ]

    parts += _html_controls(prepared)
    parts += _html_summary(prepared)

    parts.append("<h2>Findings</h2>")
    if not prepared.findings:
        parts.append("<p class='empty'>No findings.</p>")
    for finding in prepared.ranked():
        parts.append(_html_card(finding))

    parts += _html_coverage(prepared)
    parts += [
        "<footer>Confirmed findings are proven by seeded canaries, not inferred. "
        "Credentials are removed and canary values shortened, but response bodies "
        "are evidence: on a real target this page contains data the application "
        "returned. Handle it accordingly. <code>--full-evidence</code> keeps bodies "
        "verbatim and untruncated.</footer>",
        "</div></body></html>",
    ]
    return "\n".join(parts) + "\n"


def _html_controls(report: RunReport) -> list[str]:
    parts = ["<h2>Positive controls</h2>", "<ul class='controls'>"]
    if not report.controls:
        parts.append("<li class='empty'>No controls were run.</li>")
    for control in report.controls:
        css, mark = ("pass", "✅") if control.passed else ("fail", "❌")
        parts.append(
            f"<li class='{css}'>{mark} <strong>{_e(control.name)}</strong> — "
            f"{_e(control.detail)}</li>"
        )
    parts.append("</ul>")
    return parts


def _html_summary(report: RunReport) -> list[str]:
    grid = _matrix(report.findings)
    rows = []
    for severity in _SEVERITY_ORDER:
        counts = grid[severity]
        if not sum(counts.values()):
            continue
        rows.append(
            f"<tr><td>{_e(severity.value)}</td>"
            f"<td class='num'>{counts[Confidence.CONFIRMED]}</td>"
            f"<td class='num'>{counts[Confidence.SUSPECTED]}</td>"
            f"<td class='num'>{counts[Confidence.INCONCLUSIVE]}</td></tr>"
        )
    if not rows:
        rows.append(
            "<tr><td class='empty'>none</td><td class='num'>0</td>"
            "<td class='num'>0</td><td class='num'>0</td></tr>"
        )
    return [
        "<h2>Summary</h2>",
        "<div class='scroll'><table><thead><tr><th>severity</th>"
        "<th class='num'>confirmed</th><th class='num'>suspected</th>"
        "<th class='num'>inconclusive</th></tr></thead><tbody>",
        *rows,
        "</tbody></table></div>",
        f"<p class='meta'>{len(report.confirmed)} confirmed, {len(report.suspected)} suspected "
        f"across {report.endpoints_tested} of {report.endpoints_discovered} known endpoints "
        f"({len(report.results)} cross-tenant attempts).</p>",
    ]


def _html_card(finding: Finding) -> str:
    evidence = finding.evidence
    rows: list[tuple[str, str]] = []
    if evidence.request_line:
        rows.append(("Request", f"<code>{_e(evidence.request_line)}</code>"))
    if evidence.request_body:
        rows.append(("Request body", f"<code>{_e(_oneline(evidence.request_body))}</code>"))
    if evidence.response_status is not None:
        rows.append(("Response", f"<code>{_e(evidence.response_status)}</code>"))
    if evidence.matched_canary:
        rows.append(("Canary that proved it", f"<code>{_e(evidence.matched_canary)}</code>"))
    if evidence.matched_ids:
        joined = ", ".join(f"<code>{_e(i)}</code>" for i in evidence.matched_ids[:5])
        rows.append(("Leaked identifiers", joined))
    if evidence.expected_count is not None:
        rows.append(("Expected", f"<code>{_e(evidence.expected_count)}</code>"))
    if evidence.observed_count is not None:
        rows.append(("Observed", f"<code>{_e(evidence.observed_count)}</code>"))
    if evidence.file:
        suffix = f" line {_e(evidence.line)}" if evidence.line else ""
        rows.append(("Source", f"<code>{_e(evidence.file)}</code>{suffix}"))
    if evidence.note:
        rows.append(("Detail", _e(evidence.note)))
    if evidence.assumption:
        rows.append(("Assumption", _e(evidence.assumption)))

    badges = [
        f"<span class='badge sev-{_e(finding.severity.value)}'>{_e(finding.severity.value)}</span>",
        f"<span class='badge {_e(finding.confidence.value)}'>{_e(finding.confidence.value)}</span>",
        f"<span class='badge'>{_e(finding.engine.value)}</span>",
        *[f"<span class='badge'>{_e(tag)}</span>" for tag in finding.tags],
    ]

    body = [
        f"<article class='card {_e(finding.severity.value)}'>",
        f"<div class='badges'>{''.join(badges)}</div>",
        f"<h3>{_e(finding.id)} · {_e(finding.title)}</h3>",
        f"<p class='meta'><code>{_e(finding.location)}</code></p>",
    ]
    if rows:
        body.append("<dl class='kv'>")
        body += [f"<dt>{_e(label)}</dt><dd>{value}</dd>" for label, value in rows]
        body.append("</dl>")
    if evidence.response_snippet:
        body += [
            "<details><summary>Response body</summary>",
            f"<pre><code>{_e(evidence.response_snippet)}</code></pre>",
            "</details>",
        ]
    if evidence.snippet:
        body.append(f"<pre><code>{_e(evidence.snippet)}</code></pre>")
    if finding.remediation:
        body += [
            "<details open><summary>Remediation</summary>",
            _markdown_ish_to_html(finding.remediation),
            "</details>",
        ]
    body.append("</article>")
    return "".join(body)


def _markdown_ish_to_html(text: str) -> str:
    """Render the remediation templates' limited Markdown: fences and paragraphs.

    A full Markdown implementation is not needed and would be a liability — the
    only inputs are the templates in ``core/severity.py``, which we control, and
    everything is escaped either way.
    """
    parts: list[str] = []
    in_code = False
    buffer: list[str] = []

    def flush_prose() -> None:
        if buffer:
            joined = " ".join(" ".join(buffer).split())
            if joined:
                parts.append(f"<p>{_e(joined)}</p>")
            buffer.clear()

    code: list[str] = []
    for line in text.splitlines():
        if line.startswith("```"):
            if in_code:
                parts.append(f"<pre><code>{_e(chr(10).join(code))}</code></pre>")
                code.clear()
                in_code = False
            else:
                flush_prose()
                in_code = True
            continue
        if in_code:
            code.append(line)
        elif line.strip():
            buffer.append(line)
        else:
            flush_prose()
    if in_code and code:  # pragma: no cover - unbalanced fence in a template
        parts.append(f"<pre><code>{_e(chr(10).join(code))}</code></pre>")
    flush_prose()
    return "".join(parts)


def _html_coverage(report: RunReport) -> list[str]:
    enforced = _enforced(report)
    parts = ["<h2>What was checked and held</h2>"]
    if not enforced:
        parts.append(
            "<p class='empty'>No cross-tenant attempt was refused — which, with no "
            "findings either, means the run had no real coverage.</p>"
        )
        return parts

    by_attack: dict[str, int] = {}
    for result in enforced:
        by_attack[result.attack.value] = by_attack.get(result.attack.value, 0) + 1
    parts += [
        f"<p>{len(enforced)} cross-tenant attempt(s) were correctly refused.</p>",
        "<div class='scroll'><table><thead><tr><th>attack</th>"
        "<th class='num'>refused</th></tr></thead><tbody>",
        *[
            f"<tr><td>{_e(name)}</td><td class='num'>{count}</td></tr>"
            for name, count in sorted(by_attack.items())
        ],
        "</tbody></table></div>",
    ]

    inconclusive = [r for r in report.results if r.verdict is Verdict.INCONCLUSIVE]
    if inconclusive:
        parts += [
            f"<p>{len(inconclusive)} attempt(s) were <strong>inconclusive</strong> — the "
            "oracle could not decide, which is not the same as enforcement.</p>",
            "<ul>",
            *[
                f"<li><code>{_e(r.endpoint.key)}</code> ({_e(r.attack.value)}) — "
                f"{_e(r.detail)}</li>"
                for r in inconclusive[:10]
            ],
            "</ul>",
        ]
    if report.errors:
        parts += [
            "<h2>Run notes</h2><ul>",
            *[f"<li>{_e(error)}</li>" for error in report.errors],
            "</ul>",
        ]
    return parts


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #

_RENDERERS = {
    "json": render_json,
    "md": render_markdown,
    "markdown": render_markdown,
    "html": render_html,
}


# Keys the writers add on top of the model. Reading a stored report has to
# drop them, because RunReport forbids unknown fields — that strictness is
# right for user input and wrong for our own envelope.
DERIVED_KEYS = frozenset({"schema_version", "summary", "run_id", "exchanges_recorded"})


def read_report(source: str | Path) -> RunReport:
    """Load a stored ``report.json`` (or its text) back into a model."""
    text = Path(source).read_text(encoding="utf-8") if _looks_like_path(source) else str(source)
    payload = json.loads(text)
    if isinstance(payload, dict):
        for key in DERIVED_KEYS:
            payload.pop(key, None)
    return RunReport.model_validate(payload)


def _looks_like_path(source: str | Path) -> bool:
    if isinstance(source, Path):
        return True
    stripped = source.lstrip()
    return not stripped.startswith(("{", "["))


def render(report: RunReport, fmt: str, *, redact: bool = True) -> str:
    """Render in one of ``json``, ``md``, or ``html``."""
    renderer = _RENDERERS.get(fmt.lower())
    if renderer is None:
        msg = f"unknown report format {fmt!r}; choose one of json, md, html"
        raise ValueError(msg)
    return renderer(report, redact=redact)


def write_reports(
    report: RunReport,
    out_dir: str | Path,
    formats: Iterable[str],
    *,
    redact: bool = True,
) -> list[Path]:
    """Write ``report.<ext>`` for each requested format. Returns what it wrote."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for fmt in formats:
        extension = "md" if fmt.lower() in {"md", "markdown"} else fmt.lower()
        path = directory / f"report.{extension}"
        path.write_text(render(report, fmt, redact=redact), encoding="utf-8")
        written.append(path)
    return written


def summarise_controls(controls: Sequence[ControlResult]) -> str:
    """One-line control summary for terminal output."""
    passed = sum(1 for c in controls if c.passed)
    return f"{passed}/{len(controls)} positive controls passed"
