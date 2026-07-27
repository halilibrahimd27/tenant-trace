# Architecture Decision Records

MADR format. One file per decision, numbered sequentially, never edited after
acceptance — superseded records get a new ADR that points back.

| # | Decision | Status |
| --- | --- | --- |
| [0001](0001-use-madr.md) | Use MADR for architecture decisions | accepted |
| [0002](0002-dynamic-first-architecture.md) | The dynamic prober ships before the static engine | accepted |
| [0003](0003-canary-oracle.md) | Seeded canaries as the leak oracle | accepted |
| [0004](0004-hermetic-in-process-auditing.md) | The quality gate audits fixtures in-process, not in containers | accepted |
| [0005](0005-stdlib-ast-over-tree-sitter.md) | The static engine parses with the stdlib `ast` module | accepted |
| [0006](0006-seeder-owns-credentials.md) | The seeder's credentials win over configured ones | accepted |
| [0007](0007-baseline-fingerprints.md) | What goes into a finding's fingerprint | accepted |
| [0008](0008-differential-attribution.md) | Attacks establish a baseline before claiming a finding | accepted |
| [0009](0009-access-graph-from-proven-results.md) | The access graph is drawn from proven results, not from a model | accepted |
| [0010](0010-what-counts-as-evidence-of-isolation.md) | A result is evidence of isolation only if the application decided | accepted |
| [0011](0011-public-endpoints-are-a-different-bug.md) | An endpoint that serves everyone is not an endpoint that mis-scopes | accepted |
| [0012](0012-the-adapter-seam.md) | The language/framework seam must be separated before a second adapter | accepted |

Copy [`template.md`](template.md) to start a new one.
