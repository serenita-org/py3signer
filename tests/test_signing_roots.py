"""Signing-root regression tests against Web3Signer."""

from pathlib import Path

import msgspec
import pytest

from py3signer.config import Config
from py3signer.signing_roots import compute_signing_root
from py3signer.signing_types import sign_request_decoder


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
