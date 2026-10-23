"""Paired controls for the runtime-data boundaries claimed by PR #531."""

import json

import pytest

from agent_manifest._azure_verify import (
    ak_modulus_hex_from_runtime_data,
    ak_public_numbers_from_runtime_data,
)


def _packet() -> dict:
    return {"keys": [{"kid": "HCLAkPub", "kty": "RSA", "n": "AQAB_w", "e": "AQAB"}]}


@pytest.mark.parametrize("read_key", [ak_modulus_hex_from_runtime_data, ak_public_numbers_from_runtime_data])
@pytest.mark.parametrize("member,canonical,noncanonical", [("n", "AQAB_w", "AQAB_x"), ("e", "Aw", "Ax")])
def test_noncanonical_integer_has_an_accepted_canonical_twin(read_key, member, canonical, noncanonical):
    packet = _packet()
    packet["keys"][0][member] = canonical
    assert read_key(json.dumps(packet).encode()) is not None
    packet["keys"][0][member] = noncanonical
    assert read_key(json.dumps(packet).encode()) is None


@pytest.mark.parametrize("read_key", [ak_modulus_hex_from_runtime_data, ak_public_numbers_from_runtime_data])
@pytest.mark.parametrize("member", ["n", "e", "kid", "keys"])
def test_duplicate_runtime_member_has_an_accepted_unambiguous_twin(read_key, member):
    raw = json.dumps(_packet()).encode()
    assert read_key(raw) is not None
    marker = json.dumps(member).encode() + b":"
    duplicate = raw.replace(marker, marker + b" null, " + marker, 1)
    assert duplicate != raw
    assert read_key(duplicate) is None
