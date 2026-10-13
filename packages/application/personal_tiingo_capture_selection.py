"""Offline Tiingo selection consistency; no source ownership or capture authority."""

from __future__ import annotations

from datetime import datetime

from packages.adapters.market_data.tiingo_eod import (
    TiingoEodAcquisitionProfile,
    TiingoEodCaptureAuthorization,
)
from packages.adapters.market_data.tiingo_eod_calendar import TiingoEodPinnedCalendarArtifact
from packages.application.personal_forward_capture import require_capture_research_calendar_binding
from packages.domain.forward_capture_contracts import ForwardCaptureRequest
from packages.domain.personal_contracts import require_text, require_utc


class TiingoCaptureSelectionError(ValueError):
    """Static, non-sensitive denial for an inconsistent in-memory selection."""


def require_tiingo_capture_selection(
    request: ForwardCaptureRequest,
    *,
    profile: TiingoEodAcquisitionProfile,
    authorization: TiingoEodCaptureAuthorization,
    calendar: TiingoEodPinnedCalendarArtifact,
    requested_at: datetime,
) -> None:
    """Match a daily request to existing reviewed-record content without effects.

    The caller explicitly chooses the existing Tiingo-import research-calendar
    pin convention. Equal reconstructed records can pass: this function neither
    authenticates reviews nor binds source identity/rights/entitlement reference
    strings to their original evidence. It returns no permit or source token.
    Account/currency provenance, genuine clock/transport ownership and capture
    admission remain separate. No secret, clock, artifact or provider is read.

    Authorization effective dates retain their existing meaning: covered DATA
    dates, not an invented request-time expiry. Review dates are checked against
    the supplied request time; supplying that time does not qualify a clock.
    """
    try:
        if (
            type(request) is not ForwardCaptureRequest
            or type(profile) is not TiingoEodAcquisitionProfile
            or type(authorization) is not TiingoEodCaptureAuthorization
            or type(calendar) is not TiingoEodPinnedCalendarArtifact
        ):
            raise TiingoCaptureSelectionError("TIINGO_SELECTION_RECORD_TYPE_INVALID")
        require_utc(requested_at, "request time")
        request.__post_init__()
        request.source.__post_init__()
        request.producer.__post_init__()
        request.journal_key.__post_init__()
        for instrument in request.instruments:
            instrument.__post_init__()
        source = request.source
        if (request.kind, source.provider, source.environment) != (
            "daily",
            "tiingo",
            "production",
        ):
            raise TiingoCaptureSelectionError("TIINGO_SELECTION_DAILY_SOURCE_REQUIRED")
        if source.rights_status != "allowed" or source.entitlement_status != "not_required":
            raise TiingoCaptureSelectionError("TIINGO_SELECTION_SOURCE_DECLARATION_UNAVAILABLE")
        for reference in (
            source.identity_reference,
            source.rights_reference,
            source.entitlement_reference,
        ):
            if reference is None:
                raise TiingoCaptureSelectionError("TIINGO_SELECTION_SOURCE_DECLARATION_UNAVAILABLE")
            require_text(reference, "source reference")
        if not request.window_start <= requested_at < request.window_end:
            raise TiingoCaptureSelectionError("TIINGO_SELECTION_REQUEST_OUTSIDE_WINDOW")

        # Reuse bounded parsers to revalidate all nested reviewed-record content,
        # including records mutated after construction. Copies grant no authority.
        checked_profile = TiingoEodAcquisitionProfile.from_json_bytes(profile.to_json_bytes())
        checked_authorization = TiingoEodCaptureAuthorization.from_json_bytes(
            authorization.to_json_bytes()
        )
        checked_calendar = TiingoEodPinnedCalendarArtifact.from_json_bytes(calendar.to_json_bytes())
        checked_authorization.authorize(checked_profile, requested_at=requested_at)
        checked_calendar.authorize(checked_profile, requested_at=requested_at)
        scope = checked_profile.scope
        symbol = request.instruments[0].symbol
        if symbol not in scope.symbols or not scope.start_date <= request.session <= scope.end_date:
            raise TiingoCaptureSelectionError("TIINGO_SELECTION_REQUEST_OUTSIDE_SCOPE")
        require_capture_research_calendar_binding(
            request, checked_calendar.calendars_by_symbol[symbol]
        )
    except TiingoCaptureSelectionError:
        raise
    except Exception:
        raise TiingoCaptureSelectionError("TIINGO_SELECTION_INVALID") from None
