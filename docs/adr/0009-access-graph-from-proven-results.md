# ADR-0009 — The access graph is drawn from proven results, not from a model

- **Status:** accepted
- **Date:** 2026-07-27

## Context

A finding list scales badly. Six findings against a fixture read fine; the same
report against an application with two hundred endpoints is a wall, and the
sentence an operator actually needs — *"the boundary breaks in the invoices
area, and nowhere else"* — is not in it. BloodHound made the same observation
about Active Directory: the vulnerability is rarely one permission, it is the
path, and the path only becomes obvious when you draw it.

The tempting version of this feature is a **tenant reachability model**: take
the endpoint inventory, the static engine's scoping analysis, and the observed
verdicts, and infer which tenants *could* reach what. That is a different
product. It would mean claiming edges nobody walked, and it would put inferred
and proven access on the same canvas with no way for a reader to tell them
apart. This project's whole position is that a finding is a fact (ADR-0003), so
a picture whose lines are partly guesses would undo it — the graph would be the
most eye-catching thing on the page and the least trustworthy.

There is also a delivery constraint. The report is a single self-contained file
with no outbound requests, so a charting library is out: it would be either a
CDN link (breaks the guarantee) or several hundred kilobytes inlined into every
report (breaks the file).

## Decision

**Every edge in the access graph is a `ProbeResult` that already exists.**

- A `LEAKED` verdict is an edge. An `ENFORCED` verdict is the absence of one.
  `INCONCLUSIVE` draws nothing, because it means the oracle could not decide.
- Nodes are the actors and endpoints those results name. No endpoint appears
  because it looked reachable; it appears because a request reached it.
- Edges are deduplicated per `(actor, endpoint)` — one path, however many
  attacks proved it — and both the edge and the endpoint node take the **worst**
  severity involved, so the picture never under-reports.
- Severity is encoded in stroke weight as well as hue, and a key is rendered
  beneath, so the diagram survives being printed, screenshotted, or read by
  someone who cannot separate the two reds.
- A run that proved nothing draws no graph at all. An empty diagram implies a
  picture was worth drawing.

Rendered as hand-authored inline SVG: no library, no script tag, a few hundred
bytes, and it prints.

## Consequences

**Good.** The graph inherits the findings' trustworthiness exactly — it cannot
show a path that was not walked, and it needs no separate validation. It costs
nothing at run time: it is a second view of data the report already holds.

**Bad.** It is a picture of *coverage*, not of the application. An endpoint that
was never probed leaves no trace on it, which could read as "safe" to someone
skimming. Mitigated by the endpoints tile (`10/11 probed`) sitting directly
above it, and by the caption stating that refused attempts are not drawn.

**Bad.** The layout is bipartite and fixed: actors left, endpoints right. It
stays readable to a few dozen leaking endpoints and would need grouping by
resource prefix beyond that. Acceptable — an application with dozens of
confirmed leaking endpoints has a bigger problem than diagram legibility.

**Rejected.** A force-directed layout, an interactive canvas, and any edge the
prober did not walk.
