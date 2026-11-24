"""Derive the signing root from the Ethereum remote signing request."""

from typing import TYPE_CHECKING, Any

import msgspec
from ssz_z import FORKS, get_type

from .signing_types import (
    DOMAIN_AGGREGATE_AND_PROOF,
    DOMAIN_APPLICATION_BUILDER,
    DOMAIN_BEACON_ATTESTER,
    DOMAIN_BEACON_PROPOSER,
    DOMAIN_CONTRIBUTION_AND_PROOF,
    DOMAIN_DEPOSIT,
    DOMAIN_RANDAO,
    DOMAIN_SELECTION_PROOF,
    DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
    DOMAIN_VOLUNTARY_EXIT,
    AggregateAndProofSignRequest,
    AggregateAndProofV2SignRequest,
    AggregationSlotSignRequest,
    AttestationSignRequest,
    BlobSidecarSignRequest,
    BlockSignRequest,
    BlockV2SignRequest,
    DepositSignRequest,
    RandaoRevealSignRequest,
    SyncCommitteeContributionAndProofSignRequest,
    SyncCommitteeMessageSignRequest,
    SyncCommitteeSelectionProofSignRequest,
    ValidatorRegistrationSignRequest,
    VoluntaryExitSignRequest,
    validate_signing_root,
)
from .ssz_roots import (
    ZERO_ROOT,
    legacy_aggregate_root,
    legacy_block_root,
    load_ssz_json,
    validator_registration_root,
)

if TYPE_CHECKING:
    from .config import Config
    from .signing_types import SignRequest

_LEGACY_FORKS = ("phase0", "altair", "bellatrix", "capella", "deneb")
_SLOTS_PER_EPOCH = {"mainnet": 32, "gnosis": 16, "minimal": 8}


def _fork_name(value: object) -> str:
    if isinstance(value, str) and value.lower() in (*_LEGACY_FORKS, *FORKS):
        return value.lower()
    raise ValueError(f"Unsupported consensus fork: {value!r}")


def _block_root(block: dict[str, Any], preset: str) -> tuple[bytes, int]:
    fork = _fork_name(block.get("version"))
    if "block_header" in block and "block" not in block:
        value = load_ssz_json("BeaconBlockHeader", block["block_header"], preset)
    elif (
        "block" in block
        and "block_header" not in block
        and isinstance(block["block"], dict)
    ):
        if fork in ("phase0", "altair"):
            return legacy_block_root(block["block"], preset, fork)
        if fork not in FORKS:
            raise ValueError(f"BLOCK_V2 for {fork} requires a block_header")
        value = load_ssz_json("BeaconBlock", block["block"], preset, fork)
    else:
        raise ValueError("BLOCK_V2 requires exactly one block or block_header")
    return value.hash_tree_root(), int(value.field("slot"))


def _aggregate_root(data: dict[str, Any], preset: str, fork: str) -> tuple[bytes, int]:
    if fork in _LEGACY_FORKS:
        return legacy_aggregate_root(data, preset)
    value = load_ssz_json("AggregateAndProof", data, preset, fork)
    return value.hash_tree_root(), int(value.field("aggregate.data.slot"))


def _fork_signing_data(request: SignRequest, preset: str) -> tuple[bytes, bytes, int]:
    """Return the object root, domain type and duty epoch."""
    slots_per_epoch = _SLOTS_PER_EPOCH[preset]
    match request:
        case AttestationSignRequest():
            value = load_ssz_json("AttestationData", request.attestation, preset)
            return (
                value.hash_tree_root(),
                DOMAIN_BEACON_ATTESTER,
                int(value.field("target.epoch")),
            )
        case AggregationSlotSignRequest():
            root = load_ssz_json(
                "Slot", request.aggregation_slot.slot, preset
            ).hash_tree_root()
            return (
                root,
                DOMAIN_SELECTION_PROOF,
                int.from_bytes(root, "little") // slots_per_epoch,
            )
        case RandaoRevealSignRequest():
            root = load_ssz_json(
                "Epoch", request.randao_reveal.epoch, preset
            ).hash_tree_root()
            return root, DOMAIN_RANDAO, int.from_bytes(root, "little")
        case VoluntaryExitSignRequest():
            value = load_ssz_json("VoluntaryExit", request.voluntary_exit, preset)
            return (
                value.hash_tree_root(),
                DOMAIN_VOLUNTARY_EXIT,
                int(value.field("epoch")),
            )
        case BlockSignRequest():
            root, slot = legacy_block_root(request.block, preset, "phase0")
            return root, DOMAIN_BEACON_PROPOSER, slot // slots_per_epoch
        case BlockV2SignRequest():
            root, slot = _block_root(request.beacon_block, preset)
            return root, DOMAIN_BEACON_PROPOSER, slot // slots_per_epoch
        case AggregateAndProofSignRequest():
            data = msgspec.to_builtins(request.aggregate_and_proof)
            fork = (
                "electra"
                if "committee_bits" in request.aggregate_and_proof.aggregate
                else "phase0"
            )
            root, slot = _aggregate_root(data, preset, fork)
            return root, DOMAIN_AGGREGATE_AND_PROOF, slot // slots_per_epoch
        case AggregateAndProofV2SignRequest():
            versioned = request.aggregate_and_proof
            fork = _fork_name(versioned.get("version"))
            data = msgspec.convert(versioned.get("data"), dict[str, Any])
            root, slot = _aggregate_root(data, preset, fork)
            return root, DOMAIN_AGGREGATE_AND_PROOF, slot // slots_per_epoch
        case SyncCommitteeMessageSignRequest():
            message = request.sync_committee_message
            root = load_ssz_json(
                "Root", message.beacon_block_root, preset
            ).hash_tree_root()
            slot_bytes = load_ssz_json("Slot", message.slot, preset).to_ssz()
            return (
                root,
                DOMAIN_SYNC_COMMITTEE,
                int.from_bytes(slot_bytes, "little") // slots_per_epoch,
            )
        case SyncCommitteeSelectionProofSignRequest():
            value = load_ssz_json(
                "SyncAggregatorSelectionData",
                request.sync_aggregator_selection_data,
                preset,
            )
            return (
                value.hash_tree_root(),
                DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                int(value.field("slot")) // slots_per_epoch,
            )
        case SyncCommitteeContributionAndProofSignRequest():
            value = load_ssz_json(
                "ContributionAndProof", request.contribution_and_proof, preset
            )
            return (
                value.hash_tree_root(),
                DOMAIN_CONTRIBUTION_AND_PROOF,
                int(value.field("contribution.slot")) // slots_per_epoch,
            )
        case BlobSidecarSignRequest():
            raise ValueError("BLOB_SIDECAR signing is unsupported")
        case _:
            raise ValueError("Unsupported fork-dependent signing request")


def compute_signing_root(request: SignRequest, config: Config) -> bytes:
    """Compute the SSZ signing root and validate any client-supplied roots."""
    supplied_root = validate_signing_root(request.signing_root)
    api_root = validate_signing_root(request.api_signing_root)
    network = config.network_config
    preset = network.preset
    if isinstance(request, DepositSignRequest):
        deposit = request.deposit
        object_root = load_ssz_json(
            "DepositMessage",
            {
                "pubkey": deposit.pubkey,
                "withdrawal_credentials": deposit.withdrawal_credentials,
                "amount": deposit.amount,
            },
            preset,
        ).hash_tree_root()
        domain_type = DOMAIN_DEPOSIT
        fork_version = (
            network.genesis_fork_version
            if deposit.genesis_fork_version is None
            else deposit.genesis_fork_version
        )
        genesis_root = "0x" + ZERO_ROOT.hex()
    elif isinstance(request, ValidatorRegistrationSignRequest):
        registration = request.validator_registration
        object_root = validator_registration_root(
            registration.fee_recipient,
            registration.gas_limit,
            registration.timestamp,
            registration.pubkey,
            preset,
        )
        domain_type = DOMAIN_APPLICATION_BUILDER
        fork_version = network.genesis_fork_version
        genesis_root = "0x" + ZERO_ROOT.hex()
    else:
        object_root, domain_type, epoch = _fork_signing_data(request, preset)
        fork = request.fork_info.fork
        if isinstance(request, VoluntaryExitSignRequest):
            # EIP-7044 uses the fixed Capella domain for exits on Deneb and later.
            fork_version = network.capella_fork_version
        else:
            fork_epoch = load_ssz_json("Epoch", fork.epoch, preset).to_ssz()
            fork_version = (
                fork.previous_version
                if epoch < int.from_bytes(fork_epoch, "little")
                else fork.current_version
            )
        genesis_root = request.fork_info.genesis_validators_root

    fork_data_root = load_ssz_json(
        "ForkData",
        {
            "current_version": fork_version,
            "genesis_validators_root": genesis_root,
        },
        preset,
    ).hash_tree_root()
    domain = domain_type + fork_data_root[:28]
    root = get_type(
        "SigningData", fork="electra", preset=preset
    ).hash_tree_root_from_ssz(object_root + domain)
    if any(
        candidate is not None and candidate != root
        for candidate in (supplied_root, api_root)
    ):
        raise ValueError("signing_root does not match the computed signing root")
    return root
