"""Correctly isolated fixture application — global scoping (Mode B).

Import :mod:`fixtures.safe_app.main` for the application object. This app is the
precision control: every finding a run produces against it is a false positive.
"""

from __future__ import annotations

__all__: list[str] = []
