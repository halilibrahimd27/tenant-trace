"""Loading a seeder, and what happens when the one somebody wrote is wrong.

This is the only code in the project that runs a *user's* module, and it is the
first thing a first run touches. Everything here is therefore about the failure
path: a seeder that will not import, will not construct, is missing a method,
returns the wrong shape, or plants nothing at all.

None of those can be allowed to fail quietly. A run that seeded nothing has no
ground truth, so every subsequent result would be inconclusive — and a report
full of inconclusive results still renders as an audit that found no leaks.
That is exactly the outcome `RunStatus.INVALID` exists to prevent, and it starts
here, with an error message that names what the seeder did wrong.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from tenanttrace.core.models import SeededRecord, TenantLabel
from tenanttrace.probe.seeder import (
    SeederError,
    load_seeder,
    normalize_records,
    seed_tenant,
)

HERE = "tests.test_seeder_contract"


# --------------------------------------------------------------------------- #
# Seeders, good and otherwise. Module level so load_seeder can import them.
# --------------------------------------------------------------------------- #


class GoodSeeder:
    """The shape the documentation asks for."""

    def create_tenant(self, label: str) -> Mapping[str, Any]:
        return {"tenant_id": f"t-{label}", "access_token": "secret-token", "name": label}

    def auth_headers(self, tenant: Mapping[str, Any]) -> Mapping[str, str]:
        return {"Authorization": f"Bearer {tenant['access_token']}"}

    def seed_records(self, tenant: Mapping[str, Any], canary: str) -> Sequence[Any]:
        return [{"kind": "invoice", "id": "inv-1", "title": canary}]

    def cleanup(self, tenant: Mapping[str, Any]) -> None:
        return None


class NeedsClient(GoodSeeder):
    """Declares the constructor argument, so it should receive it."""

    def __init__(self, client: Any) -> None:
        self.client = client


class TakesAnything(GoodSeeder):
    """`**kwargs` gets the documented set, not every keyword in existence."""

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


class WantsSomethingElse(GoodSeeder):
    def __init__(self, database_url: str) -> None:  # never supplied
        self.database_url = database_url


class MissingCleanup:
    def create_tenant(self, label: str) -> Mapping[str, Any]:  # pragma: no cover - never called
        return {}

    def auth_headers(self, tenant: Mapping[str, Any]) -> Mapping[str, str]:  # pragma: no cover
        return {}

    def seed_records(
        self, tenant: Mapping[str, Any], canary: str
    ) -> Sequence[Any]:  # pragma: no cover
        return []


NOT_A_CLASS = "this is a string, not a seeder"


# --------------------------------------------------------------------------- #
# load_seeder
# --------------------------------------------------------------------------- #


def test_a_seeder_is_imported_and_constructed() -> None:
    seeder = load_seeder(f"{HERE}:GoodSeeder", client="a client", base_url="http://x")
    assert seeder.create_tenant("A")["tenant_id"] == "t-A"


def test_a_path_without_a_colon_says_what_the_shape_is() -> None:
    with pytest.raises(SeederError, match="module.path:ClassName"):
        load_seeder("tests.test_seeder_contract.GoodSeeder")


def test_a_module_that_does_not_import_names_the_module() -> None:
    with pytest.raises(SeederError, match="no_such_module_anywhere"):
        load_seeder("no_such_module_anywhere:Seeder")


def test_a_missing_attribute_names_the_attribute() -> None:
    with pytest.raises(SeederError, match="NoSuchClass"):
        load_seeder(f"{HERE}:NoSuchClass")


def test_constructor_arguments_are_filtered_to_what_the_seeder_declares() -> None:
    """A seeder that does not care about the HTTP client should not have to
    declare it just to be constructible."""
    plain = load_seeder(f"{HERE}:GoodSeeder", client="a client")
    assert not hasattr(plain, "client")

    wired = load_seeder(f"{HERE}:NeedsClient", client="a client", base_url="http://x")
    assert wired.client == "a client"  # type: ignore[attr-defined]


def test_a_seeder_taking_kwargs_gets_the_documented_set() -> None:
    seeder = load_seeder(f"{HERE}:TakesAnything", client="c", base_url="u", config="cfg")
    assert seeder.kwargs == {"client": "c", "base_url": "u", "config": "cfg"}  # type: ignore[attr-defined]


def test_a_constructor_that_cannot_be_satisfied_says_so() -> None:
    with pytest.raises(SeederError, match="could not construct"):
        load_seeder(f"{HERE}:WantsSomethingElse", client="c")


def test_a_seeder_missing_a_method_is_rejected_before_the_run_starts() -> None:
    """Finding this out three hundred requests in is not the same as finding
    it out now."""
    with pytest.raises(SeederError, match="missing cleanup"):
        load_seeder(f"{HERE}:MissingCleanup")


def test_something_that_is_not_callable_at_all_is_rejected() -> None:
    with pytest.raises(SeederError, match="could not construct|missing"):
        load_seeder(f"{HERE}:NOT_A_CLASS")


# --------------------------------------------------------------------------- #
# seed_tenant — the failure path is the point
# --------------------------------------------------------------------------- #


def test_seeding_produces_a_tenant_with_a_canary_and_records() -> None:
    tenant = seed_tenant(GoodSeeder(), TenantLabel.A)
    assert tenant.tenant_id == "t-A"
    assert tenant.canary.startswith("tt-canary-A-")
    assert tenant.record_ids("invoice") == ("inv-1",)
    assert tenant.headers["Authorization"].endswith("secret-token")


def test_the_token_is_kept_out_of_the_metadata_that_reaches_artifacts() -> None:
    """`metadata` is handed to cleanup and can be serialised; `headers` is
    excluded from serialisation by the model. A token in both would have a
    path to disk."""
    tenant = seed_tenant(GoodSeeder(), TenantLabel.A)
    assert "access_token" not in tenant.metadata
    assert "secret-token" not in str(dict(tenant.metadata))


def test_a_canary_is_offered_to_create_tenant_when_it_asks_for_one() -> None:
    """Some applications name the tenant at creation time and expose nothing
    else writable, so minting the canary afterwards left them unable to carry
    one at all."""
    seen: list[str] = []

    class NamesItself(GoodSeeder):
        def create_tenant(self, label: str, canary: str = "") -> Mapping[str, Any]:
            seen.append(canary)
            return {"tenant_id": f"t-{label}", "access_token": "x", "name": canary}

    tenant = seed_tenant(NamesItself(), TenantLabel.B)
    assert seen == [tenant.canary]


@pytest.mark.parametrize(
    ("method", "match"),
    [
        ("create_tenant", "create_tenant"),
        ("auth_headers", "auth_headers"),
        ("seed_records", "seed_records"),
    ],
)
def test_a_failing_step_names_the_step_and_the_tenant(method: str, match: str) -> None:
    class Broken(GoodSeeder):
        pass

    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("the application said no")

    setattr(Broken, method, explode)
    with pytest.raises(SeederError, match=match) as caught:
        seed_tenant(Broken(), TenantLabel.A)
    assert "RuntimeError" in str(caught.value)
    assert "the application said no" in str(caught.value)


def test_create_tenant_returning_the_wrong_shape_says_what_it_returned() -> None:
    class ReturnsAString(GoodSeeder):
        def create_tenant(self, label: str) -> Any:
            return "t-1"

    with pytest.raises(SeederError, match="must return a mapping, got str"):
        seed_tenant(ReturnsAString(), TenantLabel.A)


def test_planting_nothing_is_an_error_not_an_empty_run() -> None:
    """Without seeded data the oracle has nothing to look for, so every result
    would be inconclusive — and that renders as an audit that found no leaks."""

    class PlantsNothing(GoodSeeder):
        def seed_records(self, tenant: Mapping[str, Any], canary: str) -> Sequence[Any]:
            return []

    with pytest.raises(SeederError, match="planted no records"):
        seed_tenant(PlantsNothing(), TenantLabel.A)


def test_records_with_no_usable_id_count_as_no_records() -> None:
    """An id is invented for nothing: a fabricated one would later be searched
    for in responses and could only produce noise."""

    class ReturnsJunk(GoodSeeder):
        def seed_records(self, tenant: Mapping[str, Any], canary: str) -> Sequence[Any]:
            return ["not a mapping", {"title": "no id here"}, 42]

    with pytest.raises(SeederError, match="planted no records"):
        seed_tenant(ReturnsJunk(), TenantLabel.A)


def test_a_tenant_id_falls_back_to_id_then_to_the_label() -> None:
    class UsesId(GoodSeeder):
        def create_tenant(self, label: str) -> Mapping[str, Any]:
            return {"id": 77, "access_token": "x"}

    class NamesNothing(GoodSeeder):
        def create_tenant(self, label: str) -> Mapping[str, Any]:
            return {"access_token": "x"}

    assert seed_tenant(UsesId(), TenantLabel.A).tenant_id == "77"
    assert seed_tenant(NamesNothing(), TenantLabel.B).tenant_id == "B"


# --------------------------------------------------------------------------- #
# normalize_records
# --------------------------------------------------------------------------- #


def normalized(raw: Sequence[Any]) -> tuple[SeededRecord, ...]:
    return normalize_records(raw, owner=TenantLabel.B, canary="tt-canary-B-abcdef0123456789")


def test_an_api_response_can_be_returned_straight_back() -> None:
    """The common case: whatever your create call already gave you."""
    (record,) = normalized([{"id": "inv-9", "title": "x", "amount": 3}])
    assert record.id == "inv-9"
    assert record.kind == "record", "no kind given, so the default stands"
    assert record.fields == {"id": "inv-9", "title": "x", "amount": 3}


@pytest.mark.parametrize("key", ["id", "uuid", "pk"])
def test_the_identifier_is_found_under_any_of_the_usual_names(key: str) -> None:
    (record,) = normalized([{key: "abc-1", "kind": "invoice"}])
    assert record.id == "abc-1"


def test_a_seeded_record_passes_through_untouched() -> None:
    original = SeededRecord(kind="row", id="1", canary="c", owner=TenantLabel.B)
    assert normalized([original]) == (original,)


def test_a_record_can_name_the_parents_that_lead_to_it() -> None:
    """A row cannot be addressed from a row id alone."""
    (record,) = normalized([{"kind": "row", "id": "1", "path": {"table_id": 38}}])
    assert record.path == {"table_id": "38"}
    assert "path" not in record.fields


def test_a_record_may_carry_its_own_canary() -> None:
    (record,) = normalized([{"id": "1", "canary": "tt-canary-B-0000000000000001"}])
    assert record.canary == "tt-canary-B-0000000000000001"


def test_type_is_accepted_as_a_spelling_of_kind() -> None:
    (record,) = normalized([{"id": "1", "type": "document"}])
    assert record.kind == "document"


def test_a_path_that_is_not_a_mapping_is_ignored_rather_than_crashing() -> None:
    (record,) = normalized([{"id": "1", "path": "not a mapping"}])
    assert record.path == {}
