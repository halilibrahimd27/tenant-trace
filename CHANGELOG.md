# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

**Dynamic prober** — the product.
- Canary-based leak oracle with an exact verdict table; `inconclusive` is a
  first-class outcome and never a silent pass (ADR-0003).
- Positive controls before every run. A tenant that cannot read its own seeded
  data makes the run `INVALID` (exit code 3), never "clean".
- Six attack modules: `idor`, `listing`, `aggregate`, `param_override`,
  `cache`, `mass_assign`. Both directions (A→B and B→A) are probed.
- `SyncASGITransport` — audit a Python ASGI application in-process, with no
  server, port, or container. Usable from your own pytest suite (ADR-0004).
- Safety rails: host allowlist, `--i-have-authorization` for non-loopback
  targets, read-only by default, no redirect following, a rate limit shared
  across both tenant sessions, and credentials redacted where the record is
  created rather than where it is displayed.
- Run artifacts under `.tenanttrace/runs/<ts>/`, created mode `0700`.

**Static engine** — hypotheses only, never a standalone verdict.
- Parses with the stdlib `ast`; never imports or executes the code under
  analysis (ADR-0005).
- Intraprocedural reaching-definitions, scoping-mode detection (manual vs
  global), and a Python/SQLAlchemy adapter behind a `LanguageAdapter` protocol.

**Reporting and CI.**
- JSON, Markdown, and self-contained HTML reports. A report from an `INVALID`
  run opens by saying so.
- Baseline with fingerprints that survive re-seeding, endpoint reordering,
  parameter renames, and line-number churn; stale entries are reported so a
  baseline cannot rot into blanket suppression (ADR-0007).
- `action.yml` composite GitHub Action with a severity gate and a PR comment
  that never prints canary values or tokens.
- `docker compose up -d` boots both fixture applications, audits them over real
  HTTP with a real Redis, and serves the reports on `:8088`.

**CLI.** `init`, `probe`, `scan`, `report`, `metrics`, `demo`,
`validate-config`, `version`.

**Fixtures and measurement.** Two FastAPI applications sharing one schema — one
with six deliberate holes, one correctly isolated plus a legitimate
cross-tenant admin endpoint — with `labels.yaml` as the answer key and a
precision/recall gate wired into `make verify`. Currently 100% recall with zero
false positives.

### Decisions
ADR-0001 MADR · ADR-0002 dynamic-first · ADR-0003 canary oracle ·
ADR-0004 hermetic in-process auditing · ADR-0005 stdlib `ast` over tree-sitter ·
ADR-0006 seeder owns credentials · ADR-0007 baseline fingerprints ·
ADR-0008 differential attribution.
