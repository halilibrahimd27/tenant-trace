"""Deliberately insecure fixture application — manual scoping, six real holes.

Import :mod:`fixtures.vulnerable_app.main` for the application object. The
package also carries two static-only holes (:mod:`.reports` and :mod:`.jobs`)
that no HTTP route reaches: they exist so the static engine has something to
find that the prober structurally cannot.
"""

from __future__ import annotations

__all__: list[str] = []
