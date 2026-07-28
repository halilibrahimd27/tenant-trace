"""Walk a source tree, parse it, run an adapter over it, return hypotheses.

The engine is the only part of the static half that touches the filesystem, and
it is written for one hostile-input rule: **nothing it reads may run.** Files are
opened, parsed with :func:`ast.parse`, and thrown away. A file that does not
parse becomes a warning and the scan continues — a scanner that dies on the
first generated file, template stub, or Python 2 leftover in a large repository
is a scanner nobody keeps in CI.

What comes out is deliberately incomplete: every finding is ``suspected``, and
:class:`StaticScanResult` carries the scoping signal and the warnings so a report
can say what the scan could not see.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from tenanttrace.core.config import Config
from tenanttrace.core.fingerprint import with_fingerprint
from tenanttrace.core.models import Finding, ScopingMode, sort_findings
from tenanttrace.core.text import count
from tenanttrace.static import registry, scoping
from tenanttrace.static.base import LanguageAdapter, ParsedFile, ScopingSignal, StaticContext

__all__ = ["StaticScanResult", "parse_file", "scan"]


@dataclass(frozen=True, slots=True)
class StaticScanResult:
    """Everything one static scan produced, including what it could not do.

    Attributes:
        findings: Suspected findings, ranked, each carrying a fingerprint.
        scoping: Which scoping mode was used and why.
        files_scanned: How many files parsed cleanly and were analysed.
        warnings: Files skipped, missing configuration, and other reasons the
            scan is narrower than it looks. An empty finding list next to a
            warning list is not a clean bill of health, and the report must be
            able to say so.
    """

    findings: tuple[Finding, ...] = ()
    scoping: ScopingSignal = field(default_factory=lambda: ScopingSignal(ScopingMode.UNKNOWN))
    files_scanned: int = 0
    warnings: tuple[str, ...] = ()


def parse_file(path: Path, rel_path: str) -> ParsedFile:
    """Read and parse one file. Parsing only — the module is never imported.

    Args:
        path: Absolute path to read.
        rel_path: Repository-relative POSIX path used in finding locations.

    Returns:
        The parsed file.

    Raises:
        SyntaxError: When the source does not parse.
        OSError: When the file cannot be read.
        UnicodeDecodeError: When the file is not text.
    """
    source = path.read_text(encoding="utf-8")
    # ast.parse compiles to a tree and stops. It does not execute module-level
    # code, which is what makes pointing this at untrusted source acceptable.
    tree = ast.parse(source, filename=str(path))
    return ParsedFile(path=path, rel_path=rel_path, source=source, tree=tree)


def scan(path: str | Path, config: Config) -> StaticScanResult:
    """Analyse a source tree and return suspected isolation findings.

    Args:
        path: Root to walk. Usually ``[static] path`` from the config file.
        config: The loaded configuration; supplies the tenancy vocabulary, the
            adapter choice, and the exclusion globs.

    Returns:
        The findings, the scoping signal that selected the rule set, and any
        warnings. Never raises for anything the source did — a syntax error, an
        unreadable file, or an unrecognised language is a warning.
    """
    root = Path(path)
    warnings: list[str] = []

    if not root.exists():
        return StaticScanResult(
            scoping=ScopingSignal(ScopingMode.UNKNOWN, 0.0, ("nothing was scanned",)),
            warnings=(f"{root}: no such file or directory; the static engine scanned nothing",),
        )

    files, parse_warnings = _collect(root, config)
    warnings.extend(parse_warnings)
    if not files:
        return StaticScanResult(
            scoping=ScopingSignal(ScopingMode.UNKNOWN, 0.0, ("nothing was scanned",)),
            warnings=(*warnings, f"{root}: no analysable source files were found"),
        )

    adapter = registry.resolve(config.static.adapter, files)
    if adapter is None:
        return StaticScanResult(
            files_scanned=len(files),
            scoping=ScopingSignal(ScopingMode.UNKNOWN, 0.0, ("no adapter recognised this tree",)),
            warnings=(
                *warnings,
                f'[static] adapter = "auto" did not recognise {root}; set it explicitly. '
                f"Registered adapters: {', '.join(registry.available())}",
            ),
        )

    readable = tuple(f for f in files if _matches_any(f.rel_path, adapter.file_globs))
    signal = scoping.resolve_scoping(config, adapter.detect_scoping(readable))
    if signal.mode is ScopingMode.UNKNOWN:
        warnings.append(
            "scoping mode is unknown, so only mode-independent checks ran (raw SQL, "
            "cache keys, job payloads). Set [tenancy] scoping_mode to enable the rest."
        )
    if signal.mode is ScopingMode.MANUAL and not config.tenancy.scoped_models:
        warnings.append(
            "[tenancy] scoped_models is empty, so any CapWords name being queried was "
            "treated as a tenant-owned model. Listing your models makes this precise."
        )

    ctx = StaticContext.from_config(
        config,
        mode=signal.mode,
        scope_mixins=scoping.scope_mixin_names(readable),
    )

    findings = [
        with_fingerprint(finding)
        for file in readable
        for finding in _safe_findings(adapter, file, ctx, warnings)
        if not config.is_allowlisted(finding.location)
    ]

    return StaticScanResult(
        findings=tuple(sort_findings(findings)),
        scoping=signal,
        files_scanned=len(readable),
        warnings=tuple(warnings),
    )


def _safe_findings(
    adapter: LanguageAdapter,
    file: ParsedFile,
    ctx: StaticContext,
    warnings: list[str],
) -> list[Finding]:
    """Run one adapter over one file, turning a crash into a warning.

    A rule that trips over an AST shape nobody anticipated must cost one file,
    not the whole scan — and the operator has to be told which file went
    unanalysed, because "no findings here" would otherwise be a lie.
    """
    try:
        return list(adapter.find_findings(file, ctx))
    except Exception as exc:  # noqa: BLE001 - a bad rule must not end the scan
        warnings.append(f"{file.rel_path}: adapter {adapter.name} failed ({exc!r}); file skipped")
        return []


def _collect(root: Path, config: Config) -> tuple[tuple[ParsedFile, ...], list[str]]:
    """Walk, filter, and parse. Returns the files plus one warning per skip."""
    warnings: list[str] = []
    parsed: list[ParsedFile] = []
    globs = registry.discovery_globs()
    excluded = 0

    for path in _iter_paths(root):
        rel_path = _relative_path(path, root)
        if not _matches_any(rel_path, globs):
            continue
        if _is_excluded(rel_path, config.static.exclude_globs):
            excluded += 1
            continue
        try:
            parsed.append(parse_file(path, rel_path))
        except SyntaxError as exc:
            warnings.append(
                f"{rel_path}: skipped, does not parse ({exc.msg} at line {exc.lineno or 0})"
            )
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            warnings.append(f"{rel_path}: skipped, could not be read ({exc})")

    # `files_scanned` alone reads as the size of the tree. On Saleor it is
    # 1146 — out of 4300 Python files, because migrations and tests are
    # excluded by default. A reader given only the smaller number has no way to
    # know that nearly three quarters of the repository went unread, and "8
    # findings across 1146 files" is a very different claim from "…across the
    # 27% of the repository this looked at".
    if excluded:
        warnings.append(
            f"{count(excluded, 'file')} matched [static] exclude_globs "
            f"({', '.join(config.static.exclude_globs)}) and were not read. "
            "Findings below cover the remainder only."
        )

    return tuple(parsed), warnings


def _iter_paths(root: Path) -> Iterator[Path]:
    """Every file under ``root``, or ``root`` itself when it is a file."""
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def _relative_path(path: Path, root: Path) -> str:
    """A stable, repository-relative POSIX path for finding locations.

    Anchored to the working directory when possible — CI and a laptop have to
    produce the same location, and therefore the same fingerprint, for the same
    finding. Falls back to the scan root, then to the absolute path.
    """
    for base in (Path.cwd(), root if root.is_dir() else root.parent):
        try:
            return path.resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            continue
    return path.as_posix()


def _matches_any(rel_path: str, patterns: Sequence[str]) -> bool:
    return any(_matches(rel_path, pattern) for pattern in patterns)


def _is_excluded(rel_path: str, patterns: Sequence[str]) -> bool:
    return any(_matches(rel_path, pattern) for pattern in patterns)


def _matches(rel_path: str, pattern: str) -> bool:
    """``fnmatch`` against the path and its rooted form.

    ``**/tests/**`` has to exclude a top-level ``tests/`` directory as well as a
    nested one, and plain ``fnmatch`` will not match the leading segment without
    the extra slash.
    """
    return fnmatch(rel_path, pattern) or fnmatch(f"/{rel_path}", pattern)
