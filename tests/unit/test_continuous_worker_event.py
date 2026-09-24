"""Actual bounded fixture children; modeled deadline samples qualify only the seam."""

import pytest

from tests.unit import test_continuous_process as process_tests

case = process_tests.case


def test_original_event_is_exact_stable_and_has_no_replacement_setter(case):
    result = process_tests.run(case, "event_identity")
    assert result.status == "completed" and result.reason == "completed", result
    assert result.receipt is not None
    assert result.receipt.path.read_bytes() == b'{"fixture":true,"trading_authorized":false}'
    process_tests.assert_reaped(case[1])
    assert not tuple(case[0].glob(".continuous-operation-*"))


@pytest.mark.parametrize("mode", ["event_set", "event_signal", "event_deadline"])
def test_original_event_cancellation_denies_receipt_without_replacing_event(case, mode):
    result = process_tests.run(case, mode)
    # The marker proves the child reached every assertion. A pre-child probe
    # error also yields process_failed and cannot qualify Event cancellation.
    assert case[1].with_suffix(".event-checked").read_text() == mode
    assert result.status == "failed" and result.reason == "process_failed", result
    assert result.receipt is None
    process_tests.assert_reaped(case[1])
    assert not tuple(case[0].glob("continuous-receipt-*"))
    assert not tuple(case[0].glob(".continuous-operation-*"))
