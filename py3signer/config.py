"""Configuration management using msgspec Struct."""

import argparse
import multiprocessing
import re
from pathlib import Path

import msgspec
from ssz_z import PRESETS


class NetworkConfig(msgspec.Struct, frozen=True):
    """Consensus settings defined by a supported network."""

    preset: str
    genesis_fork_version: str
    capella_fork_version: str

    def __post_init__(self) -> None:
        if self.preset not in PRESETS:
            raise ValueError(
                f"PRESET_BASE must be one of {', '.join(PRESETS)}, got {self.preset!r}",
            )
        for key, version in (
            ("GENESIS_FORK_VERSION", self.genesis_fork_version),
            ("CAPELLA_FORK_VERSION", self.capella_fork_version),
        ):
            if not re.fullmatch(r"0x[0-9a-fA-F]{8}", version):
                raise ValueError(f"{key} must be a 4-byte hex value, got {version!r}")


_NETWORKS = {
    "mainnet": NetworkConfig("mainnet", "0x00000000", "0x03000000"),
    "hoodi": NetworkConfig("mainnet", "0x10000910", "0x40000910"),
    "gnosis": NetworkConfig("gnosis", "0x00000064", "0x03000064"),
    "chiado": NetworkConfig("gnosis", "0x0000006f", "0x0300006f"),
}
_NETWORK_CHOICES = (*_NETWORKS, "custom")


def _load_custom_network_config(path: Path) -> NetworkConfig:
    """Read the signing settings from a flat consensus config YAML file."""
    try:
        contents = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as e:
        raise ValueError(f"Cannot read custom network config {path}: {e}") from e

    required_keys = {"PRESET_BASE", "GENESIS_FORK_VERSION", "CAPELLA_FORK_VERSION"}
    values: dict[str, str] = {}
    for line in contents.splitlines():
        key, separator, raw_value = line.partition(":")
        key = key.rstrip()
        if not separator or key not in required_keys:
            continue
        if key in values:
            raise ValueError(f"Duplicate {key} in custom network config {path}")

        value = re.split(r"(?:^|\s)#", raw_value, maxsplit=1)[0].strip()
        if len(value) >= 2 and value[0] in ("'", '"') and value[-1] == value[0]:
            value = value[1:-1]
        values[key] = value

    missing_keys = required_keys - values.keys()
    if missing_keys:
        raise ValueError(
            f"Missing {', '.join(sorted(missing_keys))} in custom network config {path}",
        )
    try:
        return NetworkConfig(
            preset=values["PRESET_BASE"],
            genesis_fork_version=values["GENESIS_FORK_VERSION"],
            capella_fork_version=values["CAPELLA_FORK_VERSION"],
        )
    except ValueError as e:
        raise ValueError(f"Invalid custom network config {path}: {e}") from e


class Config(msgspec.Struct, frozen=True):
    """Application configuration using msgspec Struct."""

    # HTTP server settings
    host: str = "127.0.0.1"
    port: int = 8080

    # Logging
    log_level: str = "INFO"

    # Metrics settings
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 8081

    # Keystore settings
    data_dir: Path | None = None

    # Input-only keystore directories (not persisted)
    keystores_path: Path | None = None
    keystores_passwords_path: Path | None = None

    # Worker settings
    workers: int = multiprocessing.cpu_count()

    # Consensus signing settings
    network: str = "mainnet"
    custom_network_config: NetworkConfig | None = None

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        # msgspec handles basic type validation, but we need custom validation
        if self.port < 1 or self.port > 65535:
            raise ValueError(f"port must be between 1 and 65535, got {self.port}")

        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in valid_levels:
            raise ValueError(
                f"log_level must be one of {valid_levels}, got {self.log_level}",
            )

        # Validate metrics port
        if self.metrics_port < 1 or self.metrics_port > 65535:
            raise ValueError(
                f"metrics_port must be between 1 and 65535, got {self.metrics_port}",
            )

        # Validate data_dir if provided
        if self.data_dir is not None:
            if not self.data_dir.exists():
                raise ValueError(
                    f"data_dir does not exist: {self.data_dir}",
                )
            if not self.data_dir.is_dir():
                raise ValueError(
                    f"data_dir must be a directory: {self.data_dir}",
                )

        # Validate input-only keystore paths
        if self.keystores_path is not None and self.keystores_passwords_path is None:
            raise ValueError(
                "--keystores-passwords-path must be provided when --keystores-path is set",
            )
        if self.keystores_passwords_path is not None and self.keystores_path is None:
            raise ValueError(
                "--keystores-path must be provided when --keystores-passwords-path is set",
            )

        if self.keystores_path is not None:
            if not self.keystores_path.exists():
                raise ValueError(
                    f"keystores_path does not exist: {self.keystores_path}",
                )
            if not self.keystores_path.is_dir():
                raise ValueError(
                    f"keystores_path must be a directory: {self.keystores_path}",
                )

        if self.keystores_passwords_path is not None:
            if not self.keystores_passwords_path.exists():
                raise ValueError(
                    f"keystores_passwords_path does not exist: {self.keystores_passwords_path}",
                )
            if not self.keystores_passwords_path.is_dir():
                raise ValueError(
                    f"keystores_passwords_path must be a directory: {self.keystores_passwords_path}",
                )

        # Validate workers
        if self.workers < 1:
            raise ValueError(f"workers must be at least 1, got {self.workers}")

        if self.network not in _NETWORK_CHOICES:
            raise ValueError(f"network must be one of {', '.join(_NETWORK_CHOICES)}")
        if self.network == "custom" and self.custom_network_config is None:
            raise ValueError("custom network settings are required for network custom")
        if self.network != "custom" and self.custom_network_config is not None:
            raise ValueError("custom network settings require network custom")

    @property
    def network_config(self) -> NetworkConfig:
        """Return the consensus settings for the selected network."""
        if self.custom_network_config is not None:
            return self.custom_network_config
        return _NETWORKS[self.network]

    @property
    def normalized_log_level(self) -> str:
        """Return normalized uppercase log level."""
        return self.log_level.upper()


def get_config() -> Config:
    """Parse command line arguments and return configuration."""
    parser = argparse.ArgumentParser(
        description="py3signer - A Remote BLS Signer for Ethereum",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP server host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8080,
        help="HTTP server port (default: 8080)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        default=8081,
        help="Port for metrics server (default: 8081)",
    )
    parser.add_argument(
        "--metrics-host",
        default="127.0.0.1",
        help="Host for metrics server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Path to directory containing keystores (matching .json files with .txt password files)",
    )
    parser.add_argument(
        "--keystores-path",
        type=Path,
        default=None,
        help="Path to directory containing input-only keystore .json files (not persisted)",
    )
    parser.add_argument(
        "--keystores-passwords-path",
        type=Path,
        default=None,
        help="Path to directory containing input-only password .txt files (not persisted)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=multiprocessing.cpu_count(),
        help=f"Number of worker processes (default: {multiprocessing.cpu_count()})",
    )
    parser.add_argument(
        "--network",
        choices=_NETWORK_CHOICES,
        required=True,
        default=argparse.SUPPRESS,
        help="Consensus network to sign for",
    )
    parser.add_argument(
        "--network-custom-config-path",
        type=Path,
        help="Path to the consensus config YAML file required for --network custom",
    )

    args = parser.parse_args()
    custom_config_path = args.network_custom_config_path
    custom_network_config = None
    if args.network == "custom":
        if custom_config_path is None:
            raise ValueError(
                "--network-custom-config-path is required for --network custom",
            )
        custom_network_config = _load_custom_network_config(custom_config_path)
    elif custom_config_path is not None:
        raise ValueError("--network-custom-config-path requires --network custom")

    # Build config dict from CLI arguments
    config_dict: dict[str, object] = {
        "host": args.host,
        "port": args.port,
        "log_level": args.log_level,
        "metrics_port": args.metrics_port,
        "metrics_host": args.metrics_host,
        "data_dir": args.data_dir,
        "keystores_path": args.keystores_path,
        "keystores_passwords_path": args.keystores_passwords_path,
        "workers": args.workers,
        "network": args.network,
        "custom_network_config": custom_network_config,
    }

    # Create config from dict using msgspec convert
    try:
        config = msgspec.convert(config_dict, Config)
    except msgspec.ValidationError as e:
        raise ValueError(f"Configuration validation error: {e!r}") from e

    return config
