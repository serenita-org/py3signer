"""Signing-root regression tests against Web3Signer."""

from hashlib import sha256
from pathlib import Path

import msgspec
import pytest

from py3signer.config import Config, NetworkConfig
from py3signer.signing_roots import compute_signing_root
from py3signer.signing_types import (
    DOMAIN_SELECTION_PROOF,
    AggregationSlot,
    AggregationSlotSignRequest,
    Fork,
    ForkInfo,
    sign_request_decoder,
)


class SigningRootVector(msgspec.Struct, frozen=True):
    name: str
    network: str
    request: msgspec.Raw
    expected_signing_root: str


class Web3SignerVectors(msgspec.Struct, frozen=True):
    vectors: list[SigningRootVector]


_VECTORS_PATH = Path(__file__).parent / "data" / "web3signer_signing_roots.json"
_VECTORS = msgspec.json.decode(
    _VECTORS_PATH.read_bytes(), type=Web3SignerVectors
).vectors


@pytest.mark.parametrize("vector", _VECTORS, ids=[vector.name for vector in _VECTORS])
def test_signing_root_matches_web3signer(vector: SigningRootVector) -> None:
    request = sign_request_decoder.decode(vector.request)
    actual = compute_signing_root(request, Config(network=vector.network))
    assert "0x" + actual.hex() == vector.expected_signing_root


def test_minimal_preset_selects_current_fork_at_slot_eight() -> None:
    config = Config(
        network="custom",
        custom_network_config=NetworkConfig("minimal", "0x10000001", "0x40000001"),
    )
    genesis_validators_root = bytes.fromhex("ab" * 32)
    request = AggregationSlotSignRequest(
        aggregation_slot=AggregationSlot(slot="8"),
        fork_info=ForkInfo(
            fork=Fork(
                previous_version="0x10000001",
                current_version="0x20000001",
                epoch="1",
            ),
            genesis_validators_root="0x" + genesis_validators_root.hex(),
        ),
    )

    version_root = bytes.fromhex("20000001").ljust(32, b"\0")
    fork_data_root = sha256(version_root + genesis_validators_root).digest()
    domain = DOMAIN_SELECTION_PROOF + fork_data_root[:28]
    expected = sha256((8).to_bytes(32, "little") + domain).digest()
    assert compute_signing_root(request, config) == expected
