"""Attack modules.

Each takes the endpoint inventory and the two tenant sessions and yields
ProbeResults. Modules that write data are marked `mutating` and are skipped
unless --allow-mutation is set.

Adding one is deliberately cheap: implement the small ``Attack`` protocol from
``base.py``, register it below, and add a matching hole to the fixture apps
plus a line in ``fixtures/labels.yaml``. An attack module with no labelled
fixture case cannot be measured, so it does not count.
"""

from __future__ import annotations

from collections.abc import Mapping

from tenanttrace.core.models import AttackName
from tenanttrace.probe.attacks.aggregate import AggregateAttack
from tenanttrace.probe.attacks.base import Attack, AttackContext
from tenanttrace.probe.attacks.cache import CacheAttack
from tenanttrace.probe.attacks.idor import IdorAttack
from tenanttrace.probe.attacks.listing import ListingAttack
from tenanttrace.probe.attacks.mass_assign import MassAssignAttack
from tenanttrace.probe.attacks.param_override import ParamOverrideAttack

__all__ = ["ATTACKS", "Attack", "AttackContext", "build_attacks"]

ATTACKS: Mapping[AttackName, type[Attack]] = {
    AttackName.IDOR: IdorAttack,
    AttackName.LISTING: ListingAttack,
    AttackName.AGGREGATE: AggregateAttack,
    AttackName.PARAM_OVERRIDE: ParamOverrideAttack,
    AttackName.CACHE: CacheAttack,
    AttackName.MASS_ASSIGN: MassAssignAttack,
}


def build_attacks(names: tuple[AttackName, ...]) -> tuple[Attack, ...]:
    """Instantiate the requested attacks, in the order given."""
    return tuple(ATTACKS[name]() for name in names if name in ATTACKS)
