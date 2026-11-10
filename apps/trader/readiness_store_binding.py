"""Native audit metadata for a selected store, never readiness or authority.

Validation is lexical and pure. Producer-side filesystem admission belongs to
the original owner thread; these values are not registered with any wire codec.
"""

from dataclasses import dataclass, field
from pathlib import Path

from packages.domain.durable_journal_contracts import journal_identifier
from packages.domain.personal_contracts import require_digest

type _StoreIdentityValues = tuple[str, str, str, str, int, int, str]
type _StoreBindingValues = tuple[str, str, str, str, str, int, int, str]


def _validated_store_identity(values: object) -> _StoreIdentityValues:
    if type(values) is not tuple or len(values) != 7:
        raise ValueError("READINESS_STORE_IDENTITY_INVALID")
    account, binding, stream, path, device, inode, payload_sha256 = values
    if (
        any(type(value) is not str for value in (account, binding, stream, path, payload_sha256))
        or type(device) is not int
        or type(inode) is not int
    ):
        raise ValueError("READINESS_STORE_IDENTITY_INVALID")
    try:
        journal_identifier(account)
        journal_identifier(stream)
        require_digest(binding, "readiness account binding")
        require_digest(payload_sha256, "readiness configuration payload")
        lexical = Path(path)
        if (
            not lexical.is_absolute()
            or str(lexical) != path
            or ".." in lexical.parts
            or "\x00" in path
            or any(part.startswith(".env") for part in lexical.parts)
            or device < 0
            or inode < 0
        ):
            raise ValueError("identity shape")
    except ValueError:
        raise ValueError("READINESS_STORE_IDENTITY_INVALID") from None
    return account, binding, stream, path, device, inode, payload_sha256


@dataclass(frozen=True, slots=True)
class ReadinessStoreBinding:
    incarnation: str
    account_id: str
    account_binding_sha256: str
    stream_id: str
    database_path: str = field(repr=False)
    database_device: int
    database_inode: int
    configuration_payload_sha256: str

    def __post_init__(self) -> None:
        try:
            journal_identifier(self.incarnation)
            _validated_store_identity(
                (
                    self.account_id,
                    self.account_binding_sha256,
                    self.stream_id,
                    self.database_path,
                    self.database_device,
                    self.database_inode,
                    self.configuration_payload_sha256,
                )
            )
        except ValueError:
            raise ValueError("READINESS_STORE_BINDING_INVALID") from None
