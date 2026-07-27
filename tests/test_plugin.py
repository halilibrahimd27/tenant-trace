"""The Claude Code plugin, exercised rather than inspected.

This file exists because the plugin broke three times and every break was
invisible to reading it:

* the hook read its own source as JSON, because a heredoc took over stdin;
* it used ``list[str] | None``, which the system python3 on macOS is too old
  for;
* and the manifest declared ``hooks/hooks.json``, which is loaded
  automatically — so the plugin failed to load entirely while
  ``claude plugin validate`` reported it clean.

Only the last of those was caught by anything other than running it. So the
gate now runs it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parent.parent / "plugin"
MARKETPLACE = Path(__file__).resolve().parent.parent / ".claude-plugin" / "marketplace.json"
HOOK = PLUGIN / "scripts" / "scan-edited-file.sh"
REPO = Path(__file__).resolve().parent.parent


def manifest() -> dict:
    return json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())


def run_hook(
    file_path: str,
    *,
    cwd: str | None = None,
    session: str = "test",
    env: dict[str, str] | None = None,
) -> str:
    event = json.dumps(
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Edit",
            "session_id": session,
            "cwd": cwd or str(REPO),
            "tool_input": {"file_path": file_path},
        }
    )
    result = subprocess.run(
        [str(HOOK)],
        input=event,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def context_of(stdout: str) -> str:
    if not stdout.strip():
        return ""
    return json.loads(stdout)["hookSpecificOutput"]["additionalContext"]


# --------------------------------------------------------------------------- #
# Manifests
# --------------------------------------------------------------------------- #


def test_the_manifest_does_not_declare_the_standard_hooks_file() -> None:
    """It is loaded automatically; declaring it too made the plugin fail to
    load entirely, while `claude plugin validate` passed."""
    assert "hooks" not in manifest()
    assert (PLUGIN / "hooks" / "hooks.json").is_file()


def test_the_manifest_names_the_plugin_and_a_version() -> None:
    data = manifest()
    assert data["name"] == "tenant-trace"
    assert data["version"]


def test_the_hook_is_registered_for_file_edits() -> None:
    hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]
    entry = hooks["PostToolUse"][0]
    assert entry["matcher"] == "Write|Edit"
    command = entry["hooks"][0]["command"]
    assert "${CLAUDE_PLUGIN_ROOT}" in command, "an absolute path would only work here"
    assert HOOK.is_file() and HOOK.stat().st_mode & 0o111, "hook must be executable"


def test_the_repository_is_its_own_marketplace() -> None:
    """A plugin directory cannot be installed from a path without one."""
    data = json.loads(MARKETPLACE.read_text())
    assert [p["source"] for p in data["plugins"]] == ["./plugin"]
    assert data["plugins"][0]["name"] == manifest()["name"]


def test_the_skill_declares_when_to_use_it() -> None:
    skill = (PLUGIN / "skills" / "tenant-trace" / "SKILL.md").read_text()
    assert skill.startswith("---")
    assert "description:" in skill.split("---")[1]


# --------------------------------------------------------------------------- #
# The hook, run for real
# --------------------------------------------------------------------------- #


def test_it_reports_unscoped_queries_in_an_edited_file() -> None:
    out = context_of(run_hook(str(REPO / "fixtures" / "vulnerable_app" / "routes.py")))
    assert "may not be scoped to a tenant" in out
    assert "missing_tenant_filter" in out


def test_it_says_these_are_not_defects() -> None:
    """The hook must not turn a hypothesis into an instruction to edit code."""
    out = context_of(run_hook(str(REPO / "fixtures" / "vulnerable_app" / "routes.py")))
    assert "HYPOTHESES, not defects" in out
    assert "fires on correct code too" in out
    assert "Do not add a tenant predicate on the strength of this alone" in out


def test_it_is_silent_on_a_file_with_nothing_to_say() -> None:
    """A hook that comments on every edit is a hook people turn off."""
    assert run_hook(str(REPO / "src" / "tenanttrace" / "core" / "text.py")).strip() == ""


def test_it_is_silent_on_files_no_adapter_can_read() -> None:
    assert run_hook(str(REPO / "README.md")).strip() == ""


def test_a_missing_file_is_not_an_error() -> None:
    assert run_hook(str(REPO / "does-not-exist.py")).strip() == ""


def test_a_malformed_event_does_not_crash_the_edit() -> None:
    result = subprocess.run(
        [str(HOOK)], input="not json", capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0


def test_it_never_blocks(tmp_path: Path) -> None:
    """PostToolUse cannot block, but nor should the payload try to: no
    `continue: false`, no replaced tool output."""
    out = run_hook(str(REPO / "fixtures" / "vulnerable_app" / "routes.py"))
    payload = json.loads(out)
    assert set(payload) == {"hookSpecificOutput"}
    assert set(payload["hookSpecificOutput"]) == {"hookEventName", "additionalContext"}


def test_a_missing_cli_is_announced_once_not_swallowed(tmp_path: Path) -> None:
    """Silence because the tool is missing looks exactly like silence because
    nothing is wrong, and the second reading is the dangerous one.

    The CLI has to be hidden deliberately: pytest runs inside the project's own
    virtualenv, where it is very much on PATH — which is exactly why this went
    unnoticed until the hook was run against somebody else's project.
    """
    import os
    import tempfile
    import uuid

    elsewhere = tmp_path / "app"
    elsewhere.mkdir()
    target = elsewhere / "views.py"
    target.write_text("Invoice.objects.filter(status='open')\n", encoding="utf-8")

    bare = {**os.environ, "PATH": "/usr/bin:/bin"}
    session = f"isolated-{uuid.uuid4().hex[:8]}"
    marker = Path(tempfile.gettempdir()) / f"tenanttrace-hook-{session}-missing"
    marker.unlink(missing_ok=True)

    first = context_of(run_hook(str(target), cwd=str(elsewhere), session=session, env=bare))
    assert "not reachable" in first
    assert "not a clean bill of health" in first

    second = run_hook(str(target), cwd=str(elsewhere), session=session, env=bare)
    assert second.strip() == "", "the warning must not repeat on every edit"
    marker.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# The official validator, when it is available
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(shutil.which("claude") is None, reason="Claude Code CLI not installed")
def test_the_official_validator_accepts_both_manifests() -> None:
    for target in (PLUGIN, REPO):
        result = subprocess.run(
            ["claude", "plugin", "validate", str(target)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
