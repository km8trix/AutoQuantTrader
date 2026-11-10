"""Pure retained-selection projection, without readiness or new authority."""

from apps.api.contracts import (
    ContinuousSelectionCheckpointView,
    ContinuousSelectionInstrumentView,
    ContinuousSelectionResponse,
    RetainedContinuousSelectionView,
)
from packages.domain.continuous_selection_contracts import ContinuousSelectionSnapshot


def continuous_selection_response(
    snapshot: object, *, account_id: str
) -> ContinuousSelectionResponse:
    """Preserve original record validation, native counters and recorded times."""
    if type(snapshot) is not ContinuousSelectionSnapshot or snapshot.account_id != account_id:
        raise TypeError("continuous selection returned a conflicting snapshot")
    snapshot.__post_init__()
    checkpoint, selection = snapshot.checkpoint, snapshot.selection
    result = ContinuousSelectionResponse(
        account_id=snapshot.account_id,
        state=snapshot.state,
        checkpoint=None
        if checkpoint is None
        else ContinuousSelectionCheckpointView(
            stream_id=checkpoint.stream_id,
            sequence=checkpoint.sequence,
            recorded_at=checkpoint.recorded_at,
        ),
        selection=None
        if selection is None
        else RetainedContinuousSelectionView(
            generation=selection.generation,
            strategy_name=selection.strategy_name,
            strategy_version=selection.strategy_version,
            configuration_sha256=selection.configuration_sha256,
            instruments=tuple(
                ContinuousSelectionInstrumentView(instrument_id=identifier, symbol=symbol)
                for identifier, symbol in selection.instrument_symbols
            ),
            policy_id=selection.policy_id,
            enabled_for_new_exposure=selection.enabled_for_new_exposure,
            live_authorized=selection.live_authorized,
            recorded_at=selection.recorded_at,
            effective_at=selection.effective_at,
        ),
        verification=snapshot.verification,
    )
    return result
