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
git clone https://github.com/halilibrahimd27/tenant-trace
claude plugin marketplace add ./tenant-trace
claude plugin install tenant-trace@tenant-trace
```

The repository doubles as its own marketplace — `.claude-plugin/marketplace.json`
at the root points at `./plugin`.

The hook needs the `tenanttrace` CLI:

```bash
uv tool install git+https://github.com/halilibrahimd27/tenant-trace
```

It looks on `PATH`, then in the project's `.venv`/`venv`, then falls back to
`uv run` when the project has a `pyproject.toml`. It deliberately does not
fetch anything itself — starting a download because somebody saved a file is a
surprise, and a first run that takes thirty seconds on a keystroke is worse
than a hook that asks to be installed.

**If it cannot find the CLI it says so, once per session, and then goes quiet.**
That matters more than it sounds: a hook that is silent because the tool is
missing looks exactly like a hook that found no problems, and the second
reading is the dangerous one. The same applies when the CLI is present but a
scan fails — reported once, with the actual error.
