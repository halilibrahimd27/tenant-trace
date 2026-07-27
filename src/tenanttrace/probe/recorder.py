"""Run artifacts: every request and response, written down as they happen.

Two reasons this is not optional.

**Evidence.** A finding that says "tenant A read tenant B's invoice" is worth
what the transcript behind it is worth. The artifact is what a reader uses to
reproduce the leak and what an operator uses to argue with a developer who
believes the endpoint is fine.

**Falsifiability.** Recording the *enforced* results too is what makes a clean
report meaningful. Zero findings across four hundred attempts and zero findings
across zero attempts render the same headline number; only the artifact tells
them apart.

Artifacts contain real leaked tenant data, which is why ``.tenanttrace/`` is
gitignored and why credentials are redacted before anything is written rather
than while it is being displayed.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from tenanttrace.core.models import RunReport, utcnow
from tenanttrace.core.redaction import redact_credentials_in_body
from tenanttrace.probe.session import Exchange

__all__ = ["RunRecorder", "RunPaths"]

# Enough of a body to prove a leak and to see what an endpoint returns; short
# enough that an artifact of a few hundred requests stays readable and small.
SNIPPET_CHARS = 4000


@dataclass(frozen=True, slots=True)
class RunPaths:
    """Where one run's files live."""

    root: Path
    exchanges: Path
    report_json: Path

    @property
    def run_id(self) -> str:
        return self.root.name


class RunRecorder:
    """Streams exchanges to disk and writes the run's report at the end."""

    def __init__(
        self, out_dir: Path, *, redact: bool = True, started_at: datetime | None = None
    ) -> None:
        self.redact = redact
        self.started_at = started_at or utcnow()
        stamp = self.started_at.strftime("%Y%m%dT%H%M%SZ")
        root = Path(out_dir) / "runs" / stamp
        self.paths = RunPaths(
            root=root,
            exchanges=root / "exchanges.jsonl",
            report_json=root / "report.json",
        )
        self._opened = False
        self._count = 0

    # ------------------------------------------------------------------ #
    def open(self) -> RunPaths:
        """Create the run directory. Idempotent.

        The directory is created with owner-only permissions: it holds another
        tenant's data by construction, and on a shared CI runner the default
        umask is not a decision anyone made deliberately.
        """
        if not self._opened:
            self.paths.root.mkdir(parents=True, exist_ok=True)
            with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
                self.paths.root.chmod(0o700)
            self._opened = True
        return self.paths

    def record(self, exchange: Exchange) -> None:
        """Append one exchange to the transcript."""
        self.open()
        row = {
            "ts": utcnow().isoformat(),
            "tenant": exchange.label.value,
            "attack": exchange.attack,
            "method": exchange.method.value,
            "url": exchange.url,
            "status": exchange.status,
            "elapsed_ms": round(exchange.elapsed_ms, 2),
            # Headers were redacted when the Exchange was built; this is a
            # second, defensive pass in case a caller constructed one directly.
            "request_headers": dict(exchange.request_headers),
            # Truncation was the only thing applied here, while the config
            # promised "credentials are redacted". A /profile endpoint echoing
            # the caller's own non-expiring token put it verbatim into the file
            # the shipped GitHub Action uploads.
            "request_body": redact_credentials_in_body(
                _truncate(exchange.request_body, SNIPPET_CHARS)
            ),
            "response_body": redact_credentials_in_body(
                _truncate(exchange.response_text, SNIPPET_CHARS)
            ),
            "transport_error": exchange.transport_error,
        }
        with self.paths.exchanges.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        self._count += 1

    def record_all(self, exchanges: Iterable[Exchange]) -> None:
        for exchange in exchanges:
            self.record(exchange)

    def write_report(self, report: RunReport) -> Path:
        """Write the machine-readable report next to the transcript."""
        self.open()
        payload: dict[str, Any] = json.loads(report.model_dump_json())
        payload["run_id"] = self.paths.run_id
        payload["exchanges_recorded"] = self._count
        self.paths.report_json.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self.paths.report_json

    @property
    def exchange_count(self) -> int:
        return self._count


def _truncate(text: str | None, limit: int) -> str | None:
    if text is None:
        return None
    if len(text) <= limit:
        return text
    return text[:limit] + f"… [{len(text) - limit} more characters]"
