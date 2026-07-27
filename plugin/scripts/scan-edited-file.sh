#!/usr/bin/env bash
#
# PostToolUse hook: after a file is written or edited, say whether the change
# touched a query that looks unscoped.
#
# Three rules govern what this may do, and all three follow from what the
# static engine is (ADR-0002): a *hypothesis* generator whose findings stay
# `suspected` until the prober confirms them over HTTP.
#
#   1. **It never blocks.** A suspected finding is not a defect, and a hook
#      that stopped work on a hypothesis would be wrong more often than right.
#   2. **It says nothing when it has nothing to say.** A hook that comments on
#      every edit is a hook people disable, and then it protects nothing.
#   3. **It never probes.** The prober sends real traffic at a real target and
#      needs a seeder and an authorization flag. Nothing that dangerous belongs
#      on a file-save trigger.
#
# The exit code is always 0. A failure here is TenantTrace's problem, not the
# user's: an editing session should not sprout errors because a security tool
# could not run.
set -uo pipefail

# The event arrives on stdin, and the Python below is itself fed to python3 on
# stdin — so it has to be handed over out of band or the script reads its own
# source and finds no JSON in it.
TENANTTRACE_HOOK_EVENT=$(cat)
export TENANTTRACE_HOOK_EVENT

python3 - <<'PY'
# Deliberately plain: this runs under whichever python3 the editor's shell
# finds, which on macOS is still 3.9. No `X | Y` annotations, no walrus, no
# dependency beyond the standard library.
import json
import os
import shutil
import subprocess
import sys

try:
    event = json.loads(os.environ.get("TENANTTRACE_HOOK_EVENT", ""))
except Exception:
    sys.exit(0)

path = (event.get("tool_input") or {}).get("file_path") or ""
cwd = event.get("cwd") or os.getcwd()

# Python only: python_sqlalchemy is the sole adapter, so scanning anything else
# is a slow way to produce nothing.
if not path.endswith(".py") or not os.path.isfile(path):
    sys.exit(0)


def resolve():
    """How to invoke TenantTrace from wherever the editor happens to be.

    A globally installed console script is the happy path, but the common case
    for a project that vendors its own tooling is a virtualenv the editor knows
    nothing about — and a hook that silently does nothing because it looked for
    one spelling is indistinguishable from a hook that found no problems.
    """
    if shutil.which("tenanttrace"):
        return ["tenanttrace"]
    for venv in (".venv", "venv"):
        candidate = os.path.join(cwd, venv, "bin", "tenanttrace")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return [candidate]
    if shutil.which("uv") and os.path.isfile(os.path.join(cwd, "pyproject.toml")):
        return ["uv", "run", "--quiet", "tenanttrace"]
    return None


executable = resolve()
if executable is None:
    sys.exit(0)

command = [*executable, "scan", "--path", path, "--format", "json"]
for candidate in (os.path.join(cwd, "tenanttrace.toml"), "tenanttrace.toml"):
    if os.path.isfile(candidate):
        command += ["--config", candidate]
        break

try:
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=20, cwd=cwd, check=False
    )
    report = json.loads(completed.stdout)
except Exception:
    sys.exit(0)

findings = [f for f in report.get("findings", []) if f.get("confidence") == "suspected"]
if not findings:
    sys.exit(0)

listed = "\n".join(
    f"  - {f['location']} — {f['category']}" for f in findings[:5]
)
more = f"\n  …and {len(findings) - 5} more" if len(findings) > 5 else ""

context = (
    f"TenantTrace read {os.path.relpath(path, cwd)} after this edit and found "
    f"{len(findings)} quer{'y' if len(findings) == 1 else 'ies'} that may not be "
    f"scoped to a tenant:\n{listed}{more}\n\n"
    "These are HYPOTHESES, not defects, and this message is not a reason to "
    "change the code. The static engine cannot see a filter applied at a "
    "repository boundary or by a global scope — which is where well-built "
    "applications put it — so it fires on correct code too.\n\n"
    "Confirm before acting: `tenanttrace probe` proves a real leak against a "
    "running instance with a seeded canary, or check whether these call sites "
    "go through a scoped repository. Do not add a tenant predicate on the "
    "strength of this alone."
)

print(
    json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": context,
            }
        }
    )
)
PY
exit 0
