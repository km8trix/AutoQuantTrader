"""Retained local authentication facts; records are not command authority."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import ClassVar, Literal

from packages.domain.personal_contracts import ContractRecord, require_digest, require_text


@dataclass(frozen=True, slots=True)
class RuntimeOwnerAuthentication(ContractRecord):
    contract_version: ClassVar[str] = "personal-runtime-owner-authentication/1"
    owner_id: str
    command_sha256: str
    authenticated_at: datetime
    session_expires_at: datetime
    command_expires_at: datetime
    method: Literal["local-session-csrf/1"] = "local-session-csrf/1"
    environment: Literal["stateful_simulation"] = "stateful_simulation"

    def __post_init__(self) -> None:
        super(RuntimeOwnerAuthentication, self).__post_init__()
        require_text(self.owner_id, "authenticated owner")
        require_digest(self.command_sha256, "authenticated command")
        if not (
            self.authenticated_at < self.command_expires_at <= self.session_expires_at
            and self.command_expires_at <= self.authenticated_at + timedelta(seconds=60)
        ):
            raise ValueError("runtime owner authentication requires its original bounded expiry")
