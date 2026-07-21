"""Environment-backed API configuration with safe local defaults."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit


class Environment(StrEnum):
    LOCAL = "local"
    PAPER = "paper"
    LIVE = "live"


@dataclass(frozen=True, slots=True)
class LocalCredentials:
    operator_id: str = "local-operator"

    def __post_init__(self) -> None:
        if (
            type(self.operator_id) is not str
            or not self.operator_id
            or self.operator_id != self.operator_id.strip()
            or len(self.operator_id) > 128
            or any(ord(character) < 32 for character in self.operator_id)
        ):
            raise ValueError("local operator ID must be bounded, non-empty trimmed text")


@dataclass(frozen=True, slots=True)
class PaperCredentialRefs:
    account_id: str
    broker_secret_ref: str
    market_data_secret_ref: str

    def __post_init__(self) -> None:
        if not self.account_id:
            raise ValueError("paper account ID is required")
        if not self.broker_secret_ref.startswith("secret://paper/"):
            raise ValueError("paper broker credentials require a paper-scoped secret reference")
        if not self.market_data_secret_ref.startswith("secret://paper/"):
            raise ValueError("paper data credentials require a paper-scoped secret reference")


@dataclass(frozen=True, slots=True)
class LiveCredentialRefs:
    account_id: str
    broker_secret_ref: str
    market_data_secret_ref: str
    promotion_record_id: str

    def __post_init__(self) -> None:
        if not self.account_id or not self.promotion_record_id:
            raise ValueError("live account and promotion record IDs are required")
        if not self.broker_secret_ref.startswith("secret://live/"):
            raise ValueError("live broker credentials require a live-scoped secret reference")
        if not self.market_data_secret_ref.startswith("secret://live/"):
            raise ValueError("live data credentials require a live-scoped secret reference")


CredentialConfig = LocalCredentials | PaperCredentialRefs | LiveCredentialRefs


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean value: {value!r}")


def _is_literal_loopback_host(value: str) -> bool:
    if type(value) is not str or not value or value != value.strip():
        return False
    normalized = value.lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_loopback_http_origin(value: str) -> bool:
    if type(value) is not str or not value or value != value.strip():
        return False
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname is not None
        and _is_literal_loopback_host(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
        and (port is None or 1 <= port <= 65535)
    )


@dataclass(frozen=True, slots=True)
class Settings:
    environment: Environment = Environment.LOCAL
    log_level: str = "INFO"
    database_url: str = "sqlite+pysqlite:///:memory:"
    local_auth_enabled: bool = True
    cors_origins: tuple[str, ...] = ("http://localhost:5173",)
    session_secret: str = "local-development-only"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    trusted_loopback_proxy: bool = False
    data_lake_path: Path = Path(".local/data-lake")
    market_data_fixture_path: Path = Path("tests/fixtures/market_data/phase1_bars.jsonl")
    credentials: CredentialConfig = field(default_factory=LocalCredentials)

    def __post_init__(self) -> None:
        if self.environment is not Environment.LOCAL and self.local_auth_enabled:
            raise ValueError("local authentication may only be enabled in the local environment")
        if self.environment is not Environment.LOCAL and self.session_secret in {
            "",
            "local-development-only",
        }:
            raise ValueError("paper and live environments require a non-placeholder session secret")
        if not 1 <= self.api_port <= 65535:
            raise ValueError("API port must be between 1 and 65535")
        if type(self.trusted_loopback_proxy) is not bool:
            raise ValueError("trusted loopback proxy flag must be exact")
        if self.local_auth_enabled:
            if "*" in self.cors_origins:
                raise ValueError("local authentication cannot allow a wildcard CORS origin")
            if not self.cors_origins or any(
                not _is_loopback_http_origin(origin) for origin in self.cors_origins
            ):
                raise ValueError(
                    "local authentication requires explicit loopback HTTP CORS origins"
                )
            if self.trusted_loopback_proxy:
                if self.api_host not in {"0.0.0.0", "::"}:
                    raise ValueError(
                        "trusted loopback proxy mode requires an exact wildcard container bind"
                    )
            elif not _is_literal_loopback_host(self.api_host):
                raise ValueError("local authentication requires a literal loopback API bind")
        elif self.trusted_loopback_proxy:
            raise ValueError("trusted loopback proxy mode is only valid for local authentication")
        expected_type: type[CredentialConfig] = {
            Environment.LOCAL: LocalCredentials,
            Environment.PAPER: PaperCredentialRefs,
            Environment.LIVE: LiveCredentialRefs,
        }[self.environment]
        if type(self.credentials) is not expected_type:
            raise ValueError(
                f"{self.environment.value} environment requires {expected_type.__name__}"
            )

    @property
    def local_auth_transport_is_loopback_scoped(self) -> bool:
        """Whether local capability issuance is confined to a loopback transport."""

        return self.local_auth_enabled and (
            self.trusted_loopback_proxy or _is_literal_loopback_host(self.api_host)
        )

    @classmethod
    def from_env(cls) -> Settings:
        raw_origins = os.getenv("AQT_CORS_ORIGINS", "http://localhost:5173")
        origins = tuple(origin.strip() for origin in raw_origins.split(",") if origin.strip())
        environment = Environment(os.getenv("AQT_ENVIRONMENT", Environment.LOCAL.value))
        default_local_auth = environment is Environment.LOCAL
        credentials: CredentialConfig
        if environment is Environment.LOCAL:
            credentials = LocalCredentials(
                operator_id=os.getenv("AQT_LOCAL_OPERATOR_ID", "local-operator")
            )
        elif environment is Environment.PAPER:
            credentials = PaperCredentialRefs(
                account_id=os.getenv("AQT_PAPER_ACCOUNT_ID", ""),
                broker_secret_ref=os.getenv("AQT_PAPER_BROKER_SECRET_REF", ""),
                market_data_secret_ref=os.getenv("AQT_PAPER_DATA_SECRET_REF", ""),
            )
        else:
            credentials = LiveCredentialRefs(
                account_id=os.getenv("AQT_LIVE_ACCOUNT_ID", ""),
                broker_secret_ref=os.getenv("AQT_LIVE_BROKER_SECRET_REF", ""),
                market_data_secret_ref=os.getenv("AQT_LIVE_DATA_SECRET_REF", ""),
                promotion_record_id=os.getenv("AQT_LIVE_PROMOTION_RECORD_ID", ""),
            )
        return cls(
            environment=environment,
            log_level=os.getenv("AQT_LOG_LEVEL", "INFO").upper(),
            database_url=os.getenv("AQT_DATABASE_URL", "sqlite+pysqlite:///:memory:"),
            local_auth_enabled=_parse_bool(
                os.getenv("AQT_LOCAL_AUTH_ENABLED", str(default_local_auth))
            ),
            cors_origins=origins,
            session_secret=os.getenv("AQT_SESSION_SECRET", "local-development-only"),
            api_host=os.getenv("AQT_API_HOST", "127.0.0.1"),
            api_port=int(os.getenv("AQT_API_PORT", "8000")),
            trusted_loopback_proxy=_parse_bool(os.getenv("AQT_TRUSTED_LOOPBACK_PROXY", "false")),
            data_lake_path=Path(os.getenv("AQT_DATA_LAKE_PATH", ".local/data-lake")),
            market_data_fixture_path=Path(
                os.getenv(
                    "AQT_MARKET_DATA_FIXTURE_PATH",
                    "tests/fixtures/market_data/phase1_bars.jsonl",
                )
            ),
            credentials=credentials,
        )
