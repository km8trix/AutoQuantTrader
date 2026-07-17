"""Market-data source adapters."""

from packages.adapters.market_data.recorded import (
    RecordedHistoricalBarSource,
    RecordedJsonlBarSource,
)
from packages.adapters.market_data.sharadar_sfp import (
    RecordedSharadarSfpSnapshot,
    SfpCaptureAuthorization,
    SfpCaptureScope,
    SharadarSfpDataset,
    SharadarSfpError,
)
from packages.adapters.market_data.tiingo_eod import (
    TiingoEodAcquisitionProfile,
    TiingoEodAdjustedBasis,
    TiingoEodCaptureAuthorization,
    TiingoEodCaptureManifest,
    TiingoEodCaptureReceipt,
    TiingoEodDataset,
    TiingoEodError,
    TiingoEodQualificationKind,
    TiingoEodRawBasis,
    TiingoEodResponseContract,
    TiingoEodResponseObservation,
    TiingoEodRow,
    TiingoEodScope,
    qualify_tiingo_eod,
    tiingo_eod_response_contract,
)
from packages.adapters.market_data.tiingo_eod_calendar import (
    TiingoEodPinnedCalendar,
    TiingoEodPinnedCalendarArtifact,
)
from packages.adapters.market_data.tiingo_eod_capture import (
    TiingoEodApiRequest,
    TiingoEodApiResponse,
    TiingoEodApiTransport,
    TiingoEodCaptureError,
    capture_tiingo_eod,
)
from packages.adapters.market_data.tiingo_eod_lineage import (
    TIINGO_EOD_RECEIPT_LINEAGE_POLICY,
    TIINGO_EOD_RECEIPT_LINEAGE_SCHEMA_VERSION,
    TiingoEodLocalRevision,
    TiingoEodReceiptComparison,
    TiingoEodReceiptDisposition,
    TiingoEodReceiptTimeLineage,
    derive_tiingo_eod_receipt_lineage,
)
from packages.adapters.market_data.tiingo_eod_snapshot import (
    RecordedTiingoEodResearchSnapshot,
    TiingoEodCalendarBinding,
    TiingoEodVerifiedResearchSnapshot,
    verify_tiingo_eod_capture,
)

__all__ = [
    "TIINGO_EOD_RECEIPT_LINEAGE_POLICY",
    "TIINGO_EOD_RECEIPT_LINEAGE_SCHEMA_VERSION",
    "RecordedHistoricalBarSource",
    "RecordedJsonlBarSource",
    "RecordedSharadarSfpSnapshot",
    "RecordedTiingoEodResearchSnapshot",
    "SfpCaptureAuthorization",
    "SfpCaptureScope",
    "SharadarSfpDataset",
    "SharadarSfpError",
    "TiingoEodAcquisitionProfile",
    "TiingoEodAdjustedBasis",
    "TiingoEodApiRequest",
    "TiingoEodApiResponse",
    "TiingoEodApiTransport",
    "TiingoEodCalendarBinding",
    "TiingoEodCaptureAuthorization",
    "TiingoEodCaptureError",
    "TiingoEodCaptureManifest",
    "TiingoEodCaptureReceipt",
    "TiingoEodDataset",
    "TiingoEodError",
    "TiingoEodLocalRevision",
    "TiingoEodPinnedCalendar",
    "TiingoEodPinnedCalendarArtifact",
    "TiingoEodQualificationKind",
    "TiingoEodRawBasis",
    "TiingoEodReceiptComparison",
    "TiingoEodReceiptDisposition",
    "TiingoEodReceiptTimeLineage",
    "TiingoEodResponseContract",
    "TiingoEodResponseObservation",
    "TiingoEodRow",
    "TiingoEodScope",
    "TiingoEodVerifiedResearchSnapshot",
    "capture_tiingo_eod",
    "derive_tiingo_eod_receipt_lineage",
    "qualify_tiingo_eod",
    "tiingo_eod_response_contract",
    "verify_tiingo_eod_capture",
]
