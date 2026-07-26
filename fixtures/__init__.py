"""Fixture applications — the ground truth every accuracy claim is measured against.

``vulnerable_app`` really leaks and ``safe_app`` really does not; both expose the
same routes and the same response shapes and differ only in how they scope
queries. That symmetry is the point: it is what makes "the tool found the leak in
A and stayed quiet on B" a meaningful statement rather than a coincidence.

.. warning::

   ``vulnerable_app`` exists to be exploited. It ships a hardcoded fixture JWT
   secret and stores everything in a process-local in-memory database. Never run
   it anywhere reachable from a network you do not control.
"""

from __future__ import annotations

__all__: list[str] = []
