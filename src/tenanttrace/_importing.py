"""Make the directory the user ran from importable.

TenantTrace loads two things by dotted path: the seeder adapter named in
``[seeder] adapter``, and — for the bundled demo and the metrics harness — a
fixture application. Both live in the user's project, not in the installed
package.

A console script installed by pip does **not** put the current working
directory on ``sys.path`` (unlike ``python -m``, and unlike pytest, which adds
its rootdir). So ``adapter = "seeders.my_app:MySeeder"`` — the exact string the
documentation tells people to write — would fail with ``ModuleNotFoundError``
for every user, while working fine in the project's own test suite. That is a
gap worth closing explicitly rather than discovering in an issue report.

The rule is the one people already expect from a CLI: paths and module names in
your config are relative to the directory you ran the command in.
"""

from __future__ import annotations

import sys
from pathlib import Path

__all__ = ["ensure_cwd_importable"]


def ensure_cwd_importable(directory: str | Path | None = None) -> Path:
    """Put ``directory`` (default: the current one) at the front of ``sys.path``.

    Idempotent, and it prepends rather than appends: a project's own
    ``seeders`` package should win over anything of the same name further down
    the path, because it is the one the operator meant.
    """
    resolved = Path(directory or Path.cwd()).resolve()
    entry = str(resolved)
    if entry in sys.path:
        sys.path.remove(entry)
    sys.path.insert(0, entry)
    return resolved
