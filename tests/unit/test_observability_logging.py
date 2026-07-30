from __future__ import annotations

import json
import logging

from opentelemetry.sdk.trace import TracerProvider

from packages.observability.logging import JsonFormatter


def _record() -> logging.LogRecord:
    return logging.LogRecord(
        name="autoquant.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="one safe message",
        args=(),
        exc_info=None,
    )


def test_json_log_omits_trace_fields_without_a_valid_span() -> None:
    payload = json.loads(JsonFormatter().format(_record()))

    assert payload["message"] == "one safe message"
    assert "trace_id" not in payload
    assert "span_id" not in payload


def test_json_log_uses_fixed_width_ids_from_the_current_otel_span() -> None:
    provider = TracerProvider()
    tracer = provider.get_tracer("tests.logging")

    with tracer.start_as_current_span("logged-operation"):
        payload = json.loads(JsonFormatter().format(_record()))

    assert len(payload["trace_id"]) == 32
    assert len(payload["span_id"]) == 16
    assert payload["trace_sampled"] is True
    assert set(payload["trace_id"]) <= set("0123456789abcdef")
    assert set(payload["span_id"]) <= set("0123456789abcdef")
    provider.shutdown()
