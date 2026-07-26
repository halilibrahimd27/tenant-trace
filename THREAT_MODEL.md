# Threat Model

## What TenantTrace is, as an asset

It is a tool that holds **two tenants' credentials**, can **write data** to a
running application, and produces artifacts that **contain real vulnerabilities
and real leaked data**. Each of those is worth attacking.

The uncomfortable version: an attacker who gets a TenantTrace run's output has a
working exploit list for your application, plus the credentials to use it.

## Trust boundaries

```
   operator's shell / CI runner
        │
        ├── tenanttrace.toml + env  ← credentials (by reference, never by value)
        ├── seeder adapter ── YOUR code, imported and executed by design
        ├── static engine ──── reads UNTRUSTED SOURCE (parse only, never execute)
        ├── prober ─────────── speaks HTTP to the TARGET (may mutate)
        └── .tenanttrace/ ──── run artifacts: findings, requests, responses, canaries
```

## Assets

| Asset | Why it matters |
| --- | --- |
| Tenant A/B credentials | Live access to the target application |
| Run artifacts | A list of exploitable vulnerabilities plus leaked tenant data |
| Baseline file | Suppresses findings — tampering hides real bugs |
| The Action's PR comment | Public surface; must never echo tokens or canary values |
| The seeder adapter | Arbitrary code this tool imports and runs |

## STRIDE

### Static engine

| | |
| --- | --- |
| **Spoofing** | An analysed repository cannot authenticate as anything — it is data. |
| **Tampering** | Hostile source could try to make the analyser mis-report. Everything it emits is `suspected`, so a tampered result cannot fail a build on its own (rule 3). |
| **Repudiation** | Every finding carries `file::symbol`, a line number, and the source line. |
| **Info disclosure** | Findings quote source lines; the scanned repository is already readable by the operator running the scan. |
| **DoS** | A pathological file can be slow to parse. Files are parsed independently, `SyntaxError` is recorded and skipped rather than fatal, and traversal is depth-bounded. |
| **Elevation** | **The main risk, closed by construction.** `ast.parse` compiles without executing — no import, no `eval`, no plugin loading from the analysed repo ([ADR-0005](docs/adr/0005-stdlib-ast-over-tree-sitter.md)). A test asserts that scanning a file containing `os.system(...)` at module level does not run it. |

### Prober

| | |
| --- | --- |
| **Spoofing** | It holds two real credentials, so it *is* the spoofing surface. They stay in memory and in the outgoing header map; they are never rendered or written. |
| **Tampering** | An attacker on the network path could alter responses and manufacture findings. Use loopback or a trusted network — the tool does not defend against a hostile path to the target. |
| **Repudiation** | Every request and response is written to `exchanges.jsonl`, enforced attempts included. |
| **Info disclosure** | Responses contain another tenant's data by design; that is the finding. Credentials are redacted at the point the exchange is constructed, not at render time. |
| **DoS** | `max_rps` is shared across both tenant sessions, and redirects are not followed. A probe is still traffic: do not point it at production. |
| **Elevation** | `--allow-mutation` **and** `allow_mutation = true` are both required to write; either alone is refused. Non-loopback targets additionally require `--i-have-authorization`. |

### Seeder adapter

| | |
| --- | --- |
| **Spoofing** | It creates the tenants, so it defines who the prober is. |
| **Tampering** | It is your code in your repository; protect it the way you protect your test helpers. |
| **Repudiation** | Records it creates are tracked, and the finding says so when cleanup could not remove one. |
| **Info disclosure** | It handles tokens. `TenantContext.headers` is excluded from serialisation, and `cleanup()` receives tenant metadata with credentials stripped. |
| **DoS** | A slow seeder stalls the run. It runs before the controls, so a failure aborts the run rather than producing a misleading report. |
| **Elevation** | **Loading it is code execution by design** — see open question 1. |

### Run artifacts

| | |
| --- | --- |
| **Tampering** | A modified artifact could hide a finding. These are local files under the operator's control; their integrity is the machine's integrity. |
| **Repudiation** | Timestamped per run under `.tenanttrace/runs/<ts>/`. |
| **Info disclosure** | **The highest-value asset.** The run directory is created `0700`, `.tenanttrace/` is gitignored, and credential headers are redacted before anything is written. |
| **DoS** | Bounded: 4 KB per body in the transcript, 4 MB scanned per response. |

### GitHub Action

| | |
| --- | --- |
| **Spoofing** | Runs with the repository's token; the standard Actions trust model applies. |
| **Tampering** | A malicious pull request editing the baseline could suppress a real finding — which is exactly why the baseline is committed and reviewed like code ([ADR-0007](docs/adr/0007-baseline-fingerprints.md)). |
| **Repudiation** | The workflow run log is the record. |
| **Info disclosure** | **PR comments are public on public repositories.** Summaries print counts, categories, and locations. Canary values, tokens, and response bodies are never printed. |
| **DoS** | Scoped to auditing one application; `max_rps` applies. |
| **Elevation** | Secrets are referenced by name from config and injected as environment variables; they never enter the config file. |

## Controls designed in

- **Parse, never execute.** The static engine uses `ast.parse` on untrusted
  source. No import, no `eval`, no plugin loading from the analysed repository.
- **Two independent rails on the target.** `allowed_hosts` answers "did the
  operator mean this host?"; `--i-have-authorization` answers "are they allowed
  to attack it?". A typo cannot satisfy both.
- **Two independent rails on writes.** Config and command line must agree.
- **Credentials by reference.** `tenanttrace.toml` names environment variables;
  it never holds token values.
- **Redaction at the source.** Headers are redacted when the `Exchange` is
  built, so there is no code path where a token is written to disk and merely
  hidden at display time.
- **No remote `$ref` resolution.** The OpenAPI document is supplied by the
  target; following a remote reference would let the target direct this tool's
  outbound traffic.
- **No redirect following.** A 302 could otherwise move a request to a host
  outside the allowlist.
- **Positive controls.** A run that could not authenticate is `INVALID`
  (exit code 3), never "clean".

## Open questions, answered

**1. The seeder adapter is arbitrary Python loaded from a dotted path. How do we
make that trust assumption explicit without pretending to sandbox it?**

By saying it plainly and not pretending. The seeder has to call your
application's own helpers, so any sandbox strong enough to be meaningful would
also make it useless. The position is: `[seeder] adapter` is *your* code, named
in *your* config file, imported into your own process — exactly like a pytest
plugin or a `conftest.py`. That is documented in `probe/seeder.py`, in
`tenanttrace.example.toml`, and in the README, with the same instruction each
time: never point it at a module you did not write. A sandbox claim we could not
honour would be worse than the honest sentence.

**2. Run artifacts contain leaked tenant data. Redact by default, or store raw?**

**Redact by default; `--full-evidence` opts out.** Credential headers become
`<redacted>`, response bodies are truncated, and canary values render as their
last eight characters. The full body still reaches the transcript under
`.tenanttrace/`, which is gitignored and `0700`, because a finding you cannot
reproduce is not much of a finding. The *rendered report* — the artefact that
gets pasted into a ticket or attached to a build — is the redacted one.

**3. Baseline fingerprints suppress findings. Sign the file, or is review
enough?**

Review is enough, and signing would create false assurance. The baseline lives
in the repository precisely so that suppressing a finding is a diff somebody
approves. A signature would prove the file was written by a machine holding a
key, not that a human agreed with what it says. Two mitigations do carry weight:
stale entries — baselined fingerprints no longer produced — are reported, so a
baseline cannot rot into blanket suppression; and only `confirmed` findings can
be suppressed in a way that matters, since `suspected` ones never gate a build.

**4. In CI the tokens live in secrets but responses land in logs. What has to be
scrubbed before anything is printed?**

Before any output reaches a log or a PR comment: credential header values (done
at construction) and canary values (rendered as a suffix). What *is* printed:
counts by severity, categories, locations, status codes, and standards tags —
enough to act on, and not enough to hand a reader of a public log a working
exploit with the data attached. Run artifacts belong in a retention-limited
workflow artifact rather than echoed into the log; the bundled `verify.yml`
uploads them with `retention-days: 7`.

## Reporting a problem in TenantTrace itself

See [SECURITY.md](SECURITY.md). Vulnerabilities in *your* application found *by*
TenantTrace are yours to fix — that is the point of the tool.
