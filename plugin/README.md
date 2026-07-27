# TenantTrace for Claude Code

Two surfaces, and the split follows what each engine is.

**A hook, while you write.** After any edit to a Python file, the static engine
reads that one file and, if it finds a query with no visible tenant predicate,
says so. It never blocks and it never sends a request — the static engine
produces *hypotheses*, and a hook that stopped work on a hypothesis would be
wrong more often than right. It also stays quiet when it has nothing to say,
because a hook that comments on every edit is a hook people turn off.

**A skill, on demand.** `/tenant-trace` — or just asking about tenant isolation
— loads how to run a real audit, how to read an `INVALID` run, what "refused"
counts, and which categories mean what. The prober is not wired to any
automatic trigger: it sends real traffic to a real target, needs a seeder, and
requires an explicit authorization flag outside loopback.

## Install

```bash
claude plugin install tenant-trace@<marketplace>
# or, from a clone:
claude plugin install ./plugin
```

The hook needs the `tenanttrace` CLI. It looks for it on `PATH`, then in the
project's `.venv`/`venv`, then falls back to `uv run` when the project has a
`pyproject.toml`. If it finds none of those it exits silently rather than
filling an editing session with errors from a tool that is not installed.
