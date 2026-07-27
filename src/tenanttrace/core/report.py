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
from tenanttrace.core.severity import severity_for
from tenanttrace.core.text import count as _count

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


INVALID_HEADLINE = "RUN INVALID — this audit did not happen"
INVALID_BODY = (
    "Nothing in this report is evidence about tenant isolation. In particular, an "
    "empty finding list here does NOT mean the application is clean — it means the "
    "application was never successfully tested. Fix the harness and run again."
)


def _invalid_reason(report: RunReport) -> str:
    """Why this run is invalid, in the run's own words.

    A run can be invalid for several reasons — the spec would not load, the
    seeder failed, every attack crashed, the controls failed — and a banner
    that always blames the positive controls sends the reader to the wrong
    place. The harness finding carries the actual reason.
    """
    for finding in report.findings:
        if finding.evidence.note:
            return finding.evidence.note
    return report.errors[-1] if report.errors else "the run could not be completed"


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
            *[f"> {line}" for line in _wrap(_invalid_reason(prepared))],
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
        f"{_count(len(enforced), 'cross-tenant attempt')} were correctly refused:",
        "",
        "| attack | refused |",
        "| --- | ---: |",
    ]
    out += [f"| {name} | {count} |" for name, count in sorted(by_attack.items())]

    inconclusive = [r for r in report.results if r.verdict is Verdict.INCONCLUSIVE]
    if inconclusive:
        out += [
            "",
            f"{_count(len(inconclusive), 'attempt')} were **inconclusive** — the oracle could not "
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
/* Neutrals are biased toward the accent rather than inherited grey, and the
   severity ramp is deliberately separate from the accent so "critical" never
   competes with chrome for attention. Both themes are defined at the token
   level: the media query carries the OS preference, and the viewer's toggle
   stamps data-theme on the root, which has to win in both directions. */
:root {
  color-scheme: light dark;
  --bg:#F6F7F9; --card:#FFFFFF; --ink:#151A21; --muted:#5C6673; --line:#E2E6EB;
  --accent:#3E5C76; --code:#F0F2F5;
  --critical:#B3261E; --high:#B45309; --medium:#8A6D0B; --low:#0E7490;
  --info:#64748B; --ok:#15803D;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg:#0F1319; --card:#161B23; --ink:#E4E8ED; --muted:#8D97A5; --line:#242B35;
    --accent:#7FA3C4; --code:#1B212A;
    --critical:#FF6B5E; --high:#FB923C; --medium:#FBBF24; --low:#38BDF8;
    --info:#94A3B8; --ok:#4ADE80;
  }
}
:root[data-theme="dark"] {
  --bg:#0F1319; --card:#161B23; --ink:#E4E8ED; --muted:#8D97A5; --line:#242B35;
  --accent:#7FA3C4; --code:#1B212A;
  --critical:#FF6B5E; --high:#FB923C; --medium:#FBBF24; --low:#38BDF8;
  --info:#94A3B8; --ok:#4ADE80;
}
:root[data-theme="light"] {
  --bg:#F6F7F9; --card:#FFFFFF; --ink:#151A21; --muted:#5C6673; --line:#E2E6EB;
  --accent:#3E5C76; --code:#F0F2F5;
  --critical:#B3261E; --high:#B45309; --medium:#8A6D0B; --low:#0E7490;
  --info:#64748B; --ok:#15803D;
}

* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
       font:15px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif;
       -webkit-font-smoothing:antialiased; }
/* Block flow, not a flex column. Every section here is emitted as a separate
   top-level element, so a flex `gap` would apply between all of them *and*
   add to each one's own margin — the two spacing systems fight and the rhythm
   comes out uneven. In block flow adjacent margins collapse, so one rule per
   element decides the space above it and nothing doubles. */
.wrap { max-width:62rem; margin:0 auto; padding:3.5rem 1.5rem 6rem; }
code, pre, .mono { font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,monospace; }
code { background:var(--code); padding:.1rem .34rem; border-radius:.25rem; font-size:.875em; }
pre { background:var(--code); border-radius:.45rem; padding:.75rem .9rem; overflow-x:auto;
      font-size:.77rem; line-height:1.5; margin:.5rem 0 0; }
pre code { background:none; padding:0; font-size:inherit; }
.scroll { overflow-x:auto; margin:0 0 1rem; }

h1 { font-size:clamp(1.55rem,3.2vw,2rem); line-height:1.15; margin:0 0 .4rem;
     letter-spacing:-.02em; text-wrap:balance; }
/* Section labels, not headlines — the content under them carries the weight. */
h2 { font-size:.78rem; font-weight:680; letter-spacing:.12em; text-transform:uppercase;
     color:var(--muted); margin:3rem 0 1rem; }
h3 { font-size:.94rem; font-weight:640; margin:1.75rem 0 .55rem; line-height:1.35;
     letter-spacing:-.005em; text-wrap:balance; }
.card h3 { font-size:1rem; margin:0 0 .4rem; }
p.meta { color:var(--muted); font-size:.85rem; margin:0 0 1.1rem; max-width:74ch; }
.card p.meta { margin:0; max-width:none; }
/* The run line is a single fact; wrapping it reads as two. */
p.meta.run { max-width:none; margin:0 0 1.5rem; }
.eyebrow { font-size:.7rem; font-weight:650; letter-spacing:.14em; text-transform:uppercase;
           color:var(--accent); margin:0 0 .5rem; }

table { border-collapse:collapse; width:100%; font-size:.88rem; }
table.matrix { max-width:42rem; }
th,td { text-align:left; padding:.45rem .7rem; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-weight:640; font-size:.68rem; text-transform:uppercase;
     letter-spacing:.09em; }
td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }

/* The verdict block. Three states, and the colour is doing real work: it has
   to be readable as good/bad before a word of it is read. */
.verdict { display:flex; flex-direction:column; gap:.3rem; padding:1rem 1.15rem;
           border:1px solid var(--line); border-left:3px solid var(--info);
           border-radius:.55rem; background:var(--card); margin:0 0 .5rem; }
.verdict strong { font-size:1.15rem; font-weight:660; letter-spacing:-.015em; }
.verdict span { color:var(--muted); font-size:.87rem; max-width:74ch; }
.verdict.good { border-left-color:var(--ok); }
.verdict.good strong { color:var(--ok); }
.verdict.bad { border-left-color:var(--critical);
               background:color-mix(in srgb,var(--critical) 7%,var(--card)); }
.verdict.bad strong { color:var(--critical); }
.verdict.warn { border-left-color:var(--medium); }
.verdict.warn strong { color:var(--medium); }

table.index td { vertical-align:middle; }
table.index a { color:var(--accent); font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
                font-size:.84rem; }
details.glossary { margin-top:2.25rem; }
details.glossary dl.kv { margin-top:.7rem; }
details.glossary dd { color:var(--muted); max-width:62ch; }
.invalid { border:1px solid var(--critical); border-left-width:3px; border-radius:.55rem;
           padding:1.1rem 1.3rem; margin:0 0 1.5rem;
           background:color-mix(in srgb,var(--critical) 8%,transparent); }
.invalid h2 { margin:0 0 .5rem; color:var(--critical); font-size:1rem;
              letter-spacing:-.01em; text-transform:none; }
.invalid p { margin:0 0 .5rem; }

.tiles { display:grid; gap:.75rem; margin:0 0 1.5rem;
         grid-template-columns:repeat(auto-fit,minmax(9.5rem,1fr)); }
.tile { background:var(--card); border:1px solid var(--line); border-radius:.6rem;
        padding:.9rem 1rem; display:flex; flex-direction:column; gap:.15rem; }
.tile .n { font-size:1.7rem; font-weight:640; letter-spacing:-.03em; line-height:1.1;
           font-variant-numeric:tabular-nums; }
.tile .n.crit { color:var(--critical); }
.tile .k { font-size:.67rem; font-weight:640; letter-spacing:.1em; text-transform:uppercase;
           color:var(--muted); }
.tile .sub { font-size:.76rem; color:var(--muted); }

.card { border:1px solid var(--line); border-left:3px solid var(--info); border-radius:.6rem;
        padding:1.1rem 1.25rem; margin:0 0 .9rem; background:var(--card);
        display:flex; flex-direction:column; gap:.7rem; }
.card.critical { border-left-color:var(--critical); }
.card.high     { border-left-color:var(--high); }
.card.medium   { border-left-color:var(--medium); }
.card.low      { border-left-color:var(--low); }
.badges { display:flex; flex-wrap:wrap; gap:.35rem; align-items:center; }
.badge { font-size:.66rem; font-weight:660; letter-spacing:.07em; text-transform:uppercase;
         padding:.16rem .45rem; border-radius:.25rem; border:1px solid var(--line);
         color:var(--muted); white-space:nowrap; }
.badge.sev-critical { color:var(--critical); border-color:var(--critical); }
.badge.sev-high     { color:var(--high); border-color:var(--high); }
.badge.sev-medium   { color:var(--medium); border-color:var(--medium); }
.badge.sev-low      { color:var(--low); border-color:var(--low); }
.badge.confirmed    { color:var(--critical); border-color:var(--critical); }
.badge.suspected    { color:var(--medium); border-color:var(--medium); }

dl.kv { display:grid; grid-template-columns:minmax(6.5rem,max-content) 1fr;
        gap:.35rem .9rem; margin:0; font-size:.86rem; }
dl.kv dt { font-size:.65rem; font-weight:660; letter-spacing:.09em; text-transform:uppercase;
           color:var(--muted); padding-top:.16rem; }
dl.kv dd { margin:0; overflow-wrap:anywhere; }

details { margin:.35rem 0 0; }
summary { cursor:pointer; color:var(--muted); font-size:.79rem; }
summary:focus-visible { outline:2px solid var(--accent); outline-offset:2px; border-radius:.2rem; }

/* Access graph. Edges are proven results; nothing speculative is drawn. */
svg.graph { display:block; width:100%; height:auto; min-width:34rem; }
svg.graph .edge { fill:none; stroke-width:1.3; opacity:.6; }
svg.graph .edge.sev-critical { stroke:var(--critical); stroke-width:2; opacity:.85; }
svg.graph .edge.sev-high     { stroke:var(--high); stroke-width:1.5; opacity:.75; }
svg.graph .edge.sev-medium   { stroke:var(--medium); }
svg.graph .edge.sev-low      { stroke:var(--low); }
svg.graph .node rect { fill:var(--card); stroke:var(--accent); stroke-width:1.2; }
svg.graph .node text { fill:var(--ink); font-size:12px;
                       font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
svg.graph .node.actor text { font-family:inherit; font-weight:620; font-size:12px; }
svg.graph .node.target circle { fill:var(--info); }
svg.graph .node.target.sev-critical circle { fill:var(--critical); }
svg.graph .node.target.sev-high circle     { fill:var(--high); }
svg.graph .node.target.sev-medium circle   { fill:var(--medium); }

.controls { list-style:none; padding:0; margin:0 0 1.25rem; display:flex;
            flex-direction:column; gap:.4rem; font-size:.88rem; }
/* Green marks the status, not the sentence — a whole line of colour reads as
   an alarm. A *failing* control is the one case worth shouting about, because
   it means the run proves nothing. */
.legend { display:flex; flex-wrap:wrap; gap:1rem; margin:0 0 1rem;
          font-size:.72rem; color:var(--muted); letter-spacing:.04em; }
.legend span { display:inline-flex; align-items:center; gap:.35rem; }
.legend i { width:1.1rem; height:2px; border-radius:1px; background:currentColor; }
.legend .sev-critical { color:var(--critical); }
.legend .sev-high { color:var(--high); }
.legend .sev-medium { color:var(--medium); }
.legend .sev-low { color:var(--low); }
.controls li { color:var(--muted); }
.controls strong { color:var(--ink); font-weight:620; }
.controls .mark { font-weight:700; display:inline-block; width:1.05rem; }
.controls .pass .mark { color:var(--ok); }
.controls .fail, .controls .fail strong, .controls .fail .mark { color:var(--critical); }
.empty { color:var(--muted); font-style:italic; }
/* Block flow: a flex column would promote the inline <code> in this
   sentence to a full-width row and break the sentence into three. */
footer { margin-top:3.5rem; padding-top:1.1rem; border-top:1px solid var(--line);
         color:var(--muted); font-size:.79rem; line-height:1.65; max-width:78ch; }
@media (prefers-reduced-motion: reduce) {
  * { animation:none !important; transition:none !important; }
}
"""


def _took(report: RunReport) -> str:
    seconds = _duration_seconds(report)
    return f" · took {seconds:.1f}s" if seconds is not None else ""


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
        f"<p class='meta run'>{_e(prepared.target)} · run <strong>{_e(status)}</strong> · "
        f"tenanttrace {_e(prepared.tool_version)} · "
        f"{_e(prepared.started_at.replace(microsecond=0).isoformat())}{_e(_took(prepared))}</p>",
    ]

    if prepared.status is not RunStatus.VALID:
        parts += [
            "<div class='invalid'>",
            f"<h2>⚠ {_e(INVALID_HEADLINE)}</h2>",
            f"<p><strong>{_e(_invalid_reason(prepared))}</strong></p>",
            f"<p>{_e(INVALID_BODY)}</p>",
            "<ul>" + "".join(f"<li>{_e(err)}</li>" for err in prepared.errors) + "</ul>",
            "</div>",
        ]

    # Order matters more than content here. A reader opening this page has one
    # question — "is my application leaking?" — and every section before the
    # answer is a section that delays it. Method and coverage come after, where
    # they belong: as the reason to believe the answer.
    parts += _html_verdict(prepared)
    parts += _html_summary(prepared)
    parts += _html_graph(prepared)

    parts.append("<h2>Findings</h2>")
    if not prepared.findings:
        parts.append(
            "<p class='empty'>None. Every cross-tenant attempt below was refused "
            "by the application.</p>"
        )
    parts += _html_finding_index(prepared)
    for finding in prepared.ranked():
        parts.append(_html_card(finding))

    parts.append("<h2>Run integrity</h2>")
    parts.append(
        "<p class='meta'>Why the answer above can be trusted: the checks that prove "
        "the harness worked, and what the application refused.</p>"
    )
    parts += _html_controls(prepared)
    parts += _html_coverage(prepared)
    parts += _html_glossary()
    parts += [
        "<footer>Confirmed findings are proven by seeded canaries, not inferred. "
        "Credentials are removed and canary values shortened, but response bodies "
        "are evidence: on a real target this page contains data the application "
        "returned. Handle it accordingly. <code>--full-evidence</code> keeps bodies "
        "verbatim and untruncated.</footer>",
        "</div></body></html>",
    ]
    return "\n".join(parts) + "\n"


def _html_verdict(report: RunReport) -> list[str]:
    """The answer, in one sentence, before anything that explains it.

    Three outcomes, and the distinction between the last two is the whole
    point of the tool: *proven clean* and *never actually tested* look
    identical in a finding list and must never look identical here.
    """
    if report.status is not RunStatus.VALID:
        return []  # the INVALID banner already said it, louder.

    confirmed = len(report.confirmed)
    # Enforcement, not attempts. `results` includes every INCONCLUSIVE — a
    # throttled request, a redirect, an endpoint that was skipped — and calling
    # those "refused" is how a run against a rate-limiting target came back
    # claiming 168 refusals on a page whose own tile said 26.
    enforced = len(_enforced(report))
    undecided = len([r for r in report.results if r.verdict is Verdict.INCONCLUSIVE])
    if confirmed:
        tenants = len({r.actor for r in report.results if r.verdict is Verdict.LEAKED})
        return [
            "<div class='verdict bad'>",
            f"<strong>{confirmed} confirmed cross-tenant leak"
            f"{'' if confirmed == 1 else 's'}</strong>",
            f"<span>Data belonging to another tenant was read or written back to "
            f"{tenants} authenticated tenant{'' if tenants == 1 else 's'}. "
            f"Each finding below carries the request that proved it.</span>",
            "</div>",
        ]
    if not enforced:
        return [
            "<div class='verdict warn'>",
            "<strong>Nothing was proven either way</strong>",
            f"<span>Not one cross-tenant attempt was refused"
            f"{f' — {_count(undecided, 'attempt')} could not be judged' if undecided else ''}"
            ". This run is not evidence of isolation. Check the endpoint "
            "inventory, the seeded tenants, and the notes under run integrity.</span>",
            "</div>",
        ]
    return [
        "<div class='verdict good'>",
        "<strong>No cross-tenant access proven</strong>",
        f"<span>{_count(enforced, 'cross-tenant attempt')} against "
        f"{_count(report.endpoints_tested, 'endpoint')} "
        f"{'was' if enforced == 1 else 'were'} refused by the application, "
        "using real credentials for a second tenant."
        + (
            f" A further {_count(undecided, 'attempt')} could not be judged and "
            "count as neither."
            if undecided
            else ""
        )
        + " This covers what was probed — not the whole application.</span>",
        "</div>",
    ]


def _html_finding_index(report: RunReport) -> list[str]:
    """A jump list, once there are more findings than fit on a screen."""
    ranked = report.ranked()
    if len(ranked) < 3:
        return []
    rows = [
        f"<tr><td><a href='#{_e(f.id)}'>{_e(f.id)}</a></td>"
        f"<td><span class='badge sev-{_e(f.severity.value)}'>{_e(f.severity.value)}</span></td>"
        f"<td><span class='badge {_e(f.confidence.value)}'>{_e(f.confidence.value)}</span></td>"
        f"<td><code>{_e(f.location)}</code></td></tr>"
        for f in ranked
    ]
    return [
        "<div class='scroll'><table class='index'><thead><tr><th>id</th><th>severity</th>"
        "<th>confidence</th><th>where</th></tr></thead><tbody>",
        *rows,
        "</tbody></table></div>",
    ]


def _html_glossary() -> list[str]:
    """Four terms the report leans on. Collapsed — help, not preamble."""
    terms = [
        (
            "Confirmed",
            "A canary planted in another tenant's data came back in this tenant's "
            "response, or an exact count did not match. Proven, not inferred — "
            "these are the only findings that fail CI by default.",
        ),
        (
            "Suspected",
            "A hypothesis from reading the source: a query that looks unscoped. "
            "It has not been reproduced over HTTP and never gates a build on its own.",
        ),
        (
            "Positive control",
            "A tenant reading its own data. If that fails, the harness is broken and "
            "an empty finding list means nothing — so the run is marked INVALID "
            "rather than clean.",
        ),
        (
            "Inconclusive",
            "The attempt ran but the oracle could not decide — a truncated body, a "
            "redirect. Deliberately not counted as enforcement.",
        ),
    ]
    return [
        "<details class='glossary'><summary>How to read this report</summary><dl class='kv'>",
        *[f"<dt>{_e(term)}</dt><dd>{_e(body)}</dd>" for term, body in terms],
        "</dl></details>",
    ]


def _html_controls(report: RunReport) -> list[str]:
    parts = ["<h3>Positive controls</h3>", "<ul class='controls'>"]
    if not report.controls:
        parts.append("<li class='empty'>No controls were run.</li>")
    for control in report.controls:
        css, mark = ("pass", "✓") if control.passed else ("fail", "✗")
        parts.append(
            f"<li class='{css}'><span class='mark'>{mark}</span>"
            f"<strong>{_e(control.name)}</strong> — "
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

    confirmed, suspected = len(report.confirmed), len(report.suspected)
    enforced = len(_enforced(report))
    tiles = [
        (
            str(confirmed),
            "confirmed",
            "proven by seeded ground truth",
            "crit" if confirmed else "",
        ),
        (str(suspected), "suspected", "hypotheses; never gate CI", ""),
        (
            f"{report.endpoints_tested}<span class='sub'>/{report.endpoints_discovered}</span>",
            "endpoints",
            "probed of those known",
            "",
        ),
        (str(enforced), "refused", "attempts the app blocked", ""),
    ]

    parts = ["<h2>Summary</h2>", "<div class='tiles'>"]
    for value, key, sub, extra in tiles:
        parts.append(
            f"<div class='tile'><span class='n {extra}'>{value}</span>"
            f"<span class='k'>{_e(key)}</span><span class='sub'>{_e(sub)}</span></div>"
        )
    parts.append("</div>")

    if rows:
        parts += [
            "<div class='scroll'><table class='matrix'><thead><tr><th>severity</th>"
            "<th class='num'>confirmed</th><th class='num'>suspected</th>"
            "<th class='num'>inconclusive</th></tr></thead><tbody>",
            *rows,
            "</tbody></table></div>",
        ]
    parts.append(
        f"<p class='meta'>{_count(len(report.results), 'cross-tenant attempt')} across "
        f"{_count(report.endpoints_tested, 'endpoint')}.</p>"
    )
    return parts


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
        f"<article class='card {_e(finding.severity.value)}' id='{_e(finding.id)}'>",
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


def _html_graph(report: RunReport) -> list[str]:
    """An access graph: who reached what, drawn only from proven results.

    The idea is BloodHound's — in Active Directory the vulnerability is rarely
    one permission, it is the *path*, and seeing the paths is what makes a
    sprawling system comprehensible. The same is true of a large API: "four of
    these hundred endpoints are where the boundary breaks" is a sentence a
    table cannot say.

    Nothing here is new analysis. Every edge is a ``ProbeResult`` that already
    exists: a ``LEAKED`` verdict is an edge, an ``ENFORCED`` one is a
    non-edge. That keeps the picture as trustworthy as the findings — it cannot
    show a path that was not actually walked.

    Drawn as inline SVG because the report has to stay a single file with no
    outbound requests, and a charting library would be both.
    """
    leaked = [r for r in report.results if r.verdict is Verdict.LEAKED]
    if not leaked:
        return []

    # One edge per (actor, endpoint): the same endpoint proven twice in one
    # direction is one path, not two. Where two attacks proved the same edge,
    # the worse one names it — the picture should not under-report.
    edges: dict[tuple[str, str], Severity] = {}
    for result in leaked:
        key = (result.actor.value, result.endpoint.key)
        severity = severity_for(result.category_of())
        if key not in edges or severity.rank > edges[key].rank:
            edges[key] = severity

    actors = sorted({actor for actor, _ in edges})
    targets = sorted({endpoint for _, endpoint in edges})

    # A node inherits the worst path that reaches it, for the same reason.
    node_severity = {
        target: max((s for (_, t), s in edges.items() if t == target), key=lambda s: s.rank)
        for target in targets
    }

    row_h, pad_y = 34, 26
    height = max(len(targets), len(actors)) * row_h + pad_y * 2
    left_x, right_x = 96, 400
    label_x = right_x + 14
    # Endpoint keys are set in a monospace face; ~7.1px per character at 13px
    # is close enough to keep the longest one inside the canvas.
    width = int(label_x + max(len(t) for t in targets) * 7.1 + 24)

    def spread(items: list[str]) -> dict[str, float]:
        return {
            item: pad_y + (height - 2 * pad_y) * (i + 0.5) / len(items)
            for i, item in enumerate(items)
        }

    actor_y, target_y = spread(actors), spread(targets)

    parts: list[str] = [
        "<h2>Access graph</h2>",
        "<p class='meta'>Every line is a cross-tenant access this run proved. "
        "Attempts the application refused are not drawn — they are counted below.</p>",
        "<div class='scroll'>",
        f"<svg class='graph' viewBox='0 0 {width} {height}' "
        f"style='max-width:{width}px' role='img' "
        f"aria-label='Proven cross-tenant access paths'>",
    ]

    for (actor, target), severity in edges.items():
        y1, y2 = actor_y[actor], target_y[target]
        mid = (left_x + right_x) / 2
        parts.append(
            f"<path class='edge sev-{_e(severity.value)}' "
            f"d='M{left_x} {y1:.1f} C{mid} {y1:.1f} {mid} {y2:.1f} {right_x - 5} {y2:.1f}'>"
            f"<title>tenant {_e(actor)} → {_e(target)} ({_e(severity.value)})</title></path>"
        )

    for actor, y in actor_y.items():
        parts.append(
            f"<g class='node actor'><rect x='24' y='{y - 12:.1f}' width='72' height='24' rx='6'/>"
            f"<text x='60' y='{y + 4:.1f}' text-anchor='middle'>tenant {_e(actor)}</text></g>"
        )

    for target, y in target_y.items():
        severity = node_severity[target]
        parts.append(
            f"<g class='node target sev-{_e(severity.value)}'>"
            f"<circle cx='{right_x}' cy='{y:.1f}' r='4'/>"
            f"<text x='{label_x}' y='{y + 4:.1f}'>{_e(target)}</text></g>"
        )

    parts += ["</svg>", "</div>"]
    present = sorted(set(edges.values()), key=lambda sev: -sev.rank)
    keys = "".join(
        f"<span class='sev-{_e(sev.value)}'><i></i>{_e(sev.value)}</span>" for sev in present
    )
    parts.append(f"<div class='legend'>{keys}</div>")
    return parts


def _html_coverage(report: RunReport) -> list[str]:
    enforced = _enforced(report)
    parts = ["<h3>What was checked and held</h3>"]
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
        f"<p>{_count(len(enforced), 'cross-tenant attempt')} were correctly refused.</p>",
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
            f"<p>{_count(len(inconclusive), 'attempt')} were <strong>inconclusive</strong> — the "
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
            "<h3>Run notes</h3><ul>",
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
