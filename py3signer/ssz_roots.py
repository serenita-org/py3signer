"""SSZ codecs and root helpers for signing payloads."""

import re
from hashlib import sha256
from typing import Any

import msgspec
from ssz_z import NativeValue, get_type

ZERO_ROOT = bytes(32)
_MAX_VALIDATORS_PER_COMMITTEE = 2048


def load_ssz_json(
    name: str, value: object, preset: str, fork: str = "electra"
) -> NativeValue:
    """Load a decoded request payload into a native SSZ value."""
    return get_type(name, fork=fork, preset=preset).load_json(
        msgspec.json.encode(value)
    )


def _merkleize(chunks: list[bytes], limit: int) -> bytes:
    if len(chunks) > limit:
        raise ValueError(f"SSZ collection exceeds its limit of {limit}")
    level = chunks + [ZERO_ROOT] * (limit - len(chunks))
    while len(level) > 1:
        level = [
            sha256(left + right).digest()
            for left, right in zip(level[::2], level[1::2], strict=True)
        ]
    return level[0]


def _chunks(data: bytes) -> list[bytes]:
    return [
        data[offset : offset + 32].ljust(32, b"\0")
        for offset in range(0, len(data), 32)
    ]


def _mix_in_length(root: bytes, length: int) -> bytes:
    return sha256(root + length.to_bytes(32, "little")).digest()


class _LegacyAttestation(msgspec.Struct, forbid_unknown_fields=True):
    aggregation_bits: str
    data: dict[str, Any]
    signature: str


class _LegacyAggregateAndProof(msgspec.Struct, forbid_unknown_fields=True):
    aggregator_index: str
    aggregate: _LegacyAttestation
    selection_proof: str


class _LegacyIndexedAttestation(msgspec.Struct, forbid_unknown_fields=True):
    attesting_indices: list[str]
    data: dict[str, Any]
    signature: str


class _LegacyAttesterSlashing(msgspec.Struct, forbid_unknown_fields=True):
    attestation_1: _LegacyIndexedAttestation
    attestation_2: _LegacyIndexedAttestation


class _Phase0BlockBody(msgspec.Struct, forbid_unknown_fields=True):
    randao_reveal: str
    eth1_data: dict[str, Any]
    graffiti: str
    proposer_slashings: list[dict[str, Any]]
    attester_slashings: list[_LegacyAttesterSlashing]
    attestations: list[_LegacyAttestation]
    deposits: list[dict[str, Any]]
    voluntary_exits: list[dict[str, Any]]


class _AltairBlockBody(_Phase0BlockBody, forbid_unknown_fields=True):
    sync_aggregate: dict[str, Any]


def _legacy_attestation_root(attestation: _LegacyAttestation, preset: str) -> bytes:
    # Before Electra, the bitlist is limited to a single committee.
    bits = attestation.aggregation_bits
    if len(bits) > 2 + 2 * (_MAX_VALIDATORS_PER_COMMITTEE // 8 + 1) or not re.fullmatch(
        r"0x(?:[0-9a-fA-F]{2})+", bits
    ):
        raise ValueError("Invalid legacy attestation aggregation_bits")
    packed = bytearray.fromhex(bits[2:])
    if not packed[-1]:
        raise ValueError("Legacy attestation aggregation_bits is missing its delimiter")
    delimiter = packed[-1].bit_length() - 1
    length = (len(packed) - 1) * 8 + delimiter
    if length > _MAX_VALIDATORS_PER_COMMITTEE:
        raise ValueError(
            "Legacy attestation aggregation_bits exceeds the committee limit"
        )
    packed[-1] ^= 1 << delimiter
    bits_root = _mix_in_length(
        _merkleize(
            _chunks(bytes(packed[: (length + 7) // 8])),
            _MAX_VALIDATORS_PER_COMMITTEE // 256,
        ),
        length,
    )
    return _merkleize(
        [
            bits_root,
            load_ssz_json("AttestationData", attestation.data, preset).hash_tree_root(),
            load_ssz_json(
                "BLSSignature", attestation.signature, preset
            ).hash_tree_root(),
        ],
        4,
    )


def legacy_aggregate_root(data: dict[str, Any], preset: str) -> tuple[bytes, int]:
    """Hash the pre-Electra aggregate schema and return its slot."""
    aggregate = msgspec.convert(data, _LegacyAggregateAndProof)
    root = _merkleize(
        [
            load_ssz_json(
                "ValidatorIndex", aggregate.aggregator_index, preset
            ).hash_tree_root(),
            _legacy_attestation_root(aggregate.aggregate, preset),
            load_ssz_json(
                "BLSSignature", aggregate.selection_proof, preset
            ).hash_tree_root(),
        ],
        4,
    )
    return root, int(aggregate.aggregate.data["slot"])


def _legacy_indexed_attestation_root(
    attestation: _LegacyIndexedAttestation, preset: str
) -> bytes:
    length = len(attestation.attesting_indices)
    if length > _MAX_VALIDATORS_PER_COMMITTEE:
        raise ValueError("Legacy indexed attestation exceeds the committee limit")
    indices = b"".join(
        load_ssz_json("ValidatorIndex", index, preset).to_ssz()
        for index in attestation.attesting_indices
    )
    return _merkleize(
        [
            _mix_in_length(
                _merkleize(_chunks(indices), _MAX_VALIDATORS_PER_COMMITTEE // 4), length
            ),
            load_ssz_json("AttestationData", attestation.data, preset).hash_tree_root(),
            load_ssz_json(
                "BLSSignature", attestation.signature, preset
            ).hash_tree_root(),
        ],
        4,
    )


def legacy_block_root(
    block: dict[str, Any], preset: str, fork: str
) -> tuple[bytes, int]:
    """Hash a Phase0 or Altair block and return its slot."""
    if "body" not in block or "body_root" in block:
        raise ValueError("Legacy block requires a body")
    body = msgspec.convert(
        block["body"], _AltairBlockBody if fork == "altair" else _Phase0BlockBody
    )
    fields = [
        load_ssz_json("BLSSignature", body.randao_reveal, preset).hash_tree_root(),
        load_ssz_json("Eth1Data", body.eth1_data, preset).hash_tree_root(),
        load_ssz_json("Bytes32", body.graffiti, preset).hash_tree_root(),
    ]
    for name, values, limit in (
        ("ProposerSlashing", body.proposer_slashings, 16),
        ("AttesterSlashing", body.attester_slashings, 2),
        ("Attestation", body.attestations, 128),
        ("Deposit", body.deposits, 16),
        ("SignedVoluntaryExit", body.voluntary_exits, 16),
    ):
        if len(values) > limit:
            raise ValueError(f"Legacy block exceeds its limit of {limit} for {name}")
        roots = []
        for value in values:
            if isinstance(value, _LegacyAttesterSlashing):
                root = sha256(
                    _legacy_indexed_attestation_root(value.attestation_1, preset)
                    + _legacy_indexed_attestation_root(value.attestation_2, preset)
                ).digest()
            elif isinstance(value, _LegacyAttestation):
                root = _legacy_attestation_root(value, preset)
            else:
                root = load_ssz_json(name, value, preset).hash_tree_root()
            roots.append(root)
        fields.append(_mix_in_length(_merkleize(roots, limit), len(values)))
    if isinstance(body, _AltairBlockBody):
        fields.append(
            load_ssz_json("SyncAggregate", body.sync_aggregate, preset).hash_tree_root()
        )
    header = {key: value for key, value in block.items() if key != "body"}
    header["body_root"] = "0x" + _merkleize(fields, 16 if fork == "altair" else 8).hex()
    header_value = load_ssz_json("BeaconBlockHeader", header, preset)
    return header_value.hash_tree_root(), int(header_value.field("slot"))


def validator_registration_root(
    fee_recipient: str,
    gas_limit: str,
    timestamp: str,
    pubkey: str,
    preset: str,
) -> bytes:
    """Hash the builder API's ValidatorRegistrationV1 container."""
    return _merkleize(
        [
            load_ssz_json("ExecutionAddress", fee_recipient, preset).hash_tree_root(),
            load_ssz_json("Uint64", gas_limit, preset).hash_tree_root(),
            load_ssz_json("Uint64", timestamp, preset).hash_tree_root(),
            load_ssz_json("BLSPubkey", pubkey, preset).hash_tree_root(),
        ],
        4,
    )
