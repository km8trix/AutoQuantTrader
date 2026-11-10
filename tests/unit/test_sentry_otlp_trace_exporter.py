from __future__ import annotations

from collections.abc import Sequence

import pytest
import requests
from opentelemetry.exporter.otlp.proto.http import Compression
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.trace import Status, StatusCode

from packages.observability.sentry_otlp import (
    SENTRY_OTLP_AUTH_API_VERSION,
    SENTRY_OTLP_CLIENT_ID,
    SENTRY_OTLP_ENVIRONMENT,
    SENTRY_OTLP_EXPORT_TIMEOUT_SECONDS,
    SENTRY_OTLP_PROVIDER_ID,
    SENTRY_OTLP_SERVICE_NAME,
    SentryOtlpConfiguration,
    SentryOtlpConfigurationError,
    SentryOtlpExporterError,
    SentryOtlpTraceExporter,
    build_sentry_otlp_trace_exporter,
)
from packages.observability.tracing import TRADING_TRACE_CONTRACT_VERSION

PUBLIC_KEY = "0123456789abcdef0123456789abcdef"
SENTRY_HOST = "o4501234567890123.ingest.us.sentry.io"
PROJECT_ID = "4509876543210001"
DSN = f"https://{PUBLIC_KEY}@{SENTRY_HOST}/{PROJECT_ID}"
RELEASE = "release-2026-07-29.1"
SENSITIVE_ACCOUNT = "paper-account-sensitive-identifier"
SENSITIVE_FACT = "position-SPY-qty-100-price-419.25"
SENSITIVE_EVENT = "database-password-and-raw-provider-response"


class CapturingExporter(SpanExporter):
    def __init__(
        self,
        *,
        export_result: SpanExportResult = SpanExportResult.SUCCESS,
        fail_export: bool = False,
        fail_shutdown: bool = False,
    ) -> None:
        self.export_result = export_result
        self.fail_export = fail_export
        self.fail_shutdown = fail_shutdown
        self.batches: list[tuple[ReadableSpan, ...]] = []
        self.shutdown_called = False
        self.flush_timeouts: list[int] = []

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        if self.fail_export:
            raise RuntimeError(SENSITIVE_EVENT)
        self.batches.append(tuple(spans))
        return self.export_result

    def shutdown(self) -> None:
        self.shutdown_called = True
        if self.fail_shutdown:
            raise RuntimeError(SENSITIVE_EVENT)

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        self.flush_timeouts.append(timeout_millis)
        return True


def _configuration() -> SentryOtlpConfiguration:
    return SentryOtlpConfiguration(dsn=DSN, release=RELEASE)


def _pinned_resource(**updates: str) -> Resource:
    attributes = {
        "service.name": SENTRY_OTLP_SERVICE_NAME,
        "service.version": RELEASE,
        "deployment.environment.name": SENTRY_OTLP_ENVIRONMENT,
    }
    attributes.update(updates)
    return Resource.create(attributes)


def test_factory_derives_official_sentry_endpoint_and_auth_without_network() -> None:
    captured: dict[str, object] = {}
    inner = CapturingExporter()

    def factory(**kwargs: object) -> object:
        captured.update(kwargs)
        return inner

    exporter = build_sentry_otlp_trace_exporter(
        _configuration(),
        exporter_factory=factory,
    )

    assert captured["endpoint"] == (
        f"https://{SENTRY_HOST}/api/{PROJECT_ID}/integration/otlp/v1/traces/"
    )
    assert captured["headers"] == {
        "X-Sentry-Auth": (
            "Sentry "
            f"sentry_version={SENTRY_OTLP_AUTH_API_VERSION}, "
            f"sentry_client={SENTRY_OTLP_CLIENT_ID}, "
            f"sentry_key={PUBLIC_KEY}"
        )
    }
    assert captured["timeout"] == SENTRY_OTLP_EXPORT_TIMEOUT_SECONDS
    assert captured["certificate_file"] is True
    assert captured["compression"] is Compression.NoCompression
    session = captured["session"]
    assert isinstance(session, requests.Session)
    assert not session.trust_env
    assert exporter.provider_id == SENTRY_OTLP_PROVIDER_ID
    assert exporter.diagnostic_only
    assert not exporter.trading_effect_authorized
    assert not exporter.broker_action_authorized

    rendered = f"{_configuration()!r} {exporter!r} {exporter!s}"
    assert "[REDACTED]" in rendered
    assert DSN not in rendered
    assert PUBLIC_KEY not in rendered
    assert SENTRY_HOST not in rendered
    assert PROJECT_ID not in rendered
    assert "X-Sentry-Auth" not in rendered


def test_official_otlp_exporter_constructs_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_post(*_: object, **__: object) -> object:
        raise AssertionError("exporter construction must not perform network I/O")

    monkeypatch.setattr(requests.Session, "post", forbidden_post)
    exporter = build_sentry_otlp_trace_exporter(_configuration())

    assert type(exporter) is SentryOtlpTraceExporter
    exporter.shutdown()


@pytest.mark.parametrize(
    "dsn",
    (
        f"http://{PUBLIC_KEY}@{SENTRY_HOST}/{PROJECT_ID}",
        f"https://{PUBLIC_KEY}@example.invalid/{PROJECT_ID}",
        f"https://{PUBLIC_KEY}:private-secret@{SENTRY_HOST}/{PROJECT_ID}",
        f"https://{PUBLIC_KEY}@{SENTRY_HOST}:443/{PROJECT_ID}",
        f"https://{PUBLIC_KEY}@{SENTRY_HOST}/{PROJECT_ID}?secret=value",
        f"https://not-a-public-key@{SENTRY_HOST}/{PROJECT_ID}",
        f"https://{PUBLIC_KEY}@{SENTRY_HOST}/api/{PROJECT_ID}",
        f"https://{PUBLIC_KEY}@o0.ingest.sentry.io/{PROJECT_ID}",
    ),
)
def test_factory_rejects_noncanonical_or_noncloud_dsn_without_leaking_it(
    dsn: str,
) -> None:
    with pytest.raises(SentryOtlpConfigurationError) as failure:
        SentryOtlpConfiguration(dsn=dsn, release=RELEASE)

    rendered = f"{failure.value!s} {failure.value!r}"
    assert dsn not in rendered
    assert PUBLIC_KEY not in rendered
    assert "private-secret" not in rendered


@pytest.mark.parametrize(
    "updates",
    (
        {"service_name": "another-service"},
        {"environment": "live"},
        {"release": "release contains spaces"},
    ),
)
def test_configuration_requires_fixed_service_environment_and_safe_release(
    updates: dict[str, str],
) -> None:
    arguments = {"dsn": DSN, "release": RELEASE, **updates}
    with pytest.raises(SentryOtlpConfigurationError):
        SentryOtlpConfiguration(**arguments)


def test_factory_sanitizes_constructor_failures_and_rejects_invalid_exporter() -> None:
    raw_failure = DSN + " X-Sentry-Auth private-header"

    def failing_factory(**_: object) -> object:
        raise RuntimeError(raw_failure)

    with pytest.raises(SentryOtlpConfigurationError) as failure:
        build_sentry_otlp_trace_exporter(
            _configuration(),
            exporter_factory=failing_factory,
        )
    assert raw_failure not in str(failure.value)
    assert PUBLIC_KEY not in repr(failure.value)

    with pytest.raises(SentryOtlpConfigurationError, match="invalid exporter"):
        build_sentry_otlp_trace_exporter(
            _configuration(),
            exporter_factory=lambda **_: object(),
        )


def test_exporter_removes_sensitive_span_resource_event_link_and_status_data() -> None:
    inner = CapturingExporter()
    exporter = SentryOtlpTraceExporter(configuration=_configuration(), inner=inner)
    provider = TracerProvider(
        resource=_pinned_resource(
            **{
                "host.name": "sensitive-hostname",
                "process.command_args": "raw-command-and-secret",
            }
        )
    )
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("sensitive-instrumentation-scope", "private-version")

    with tracer.start_as_current_span(
        SENSITIVE_FACT,
        attributes={
            "autoquant.account.id": SENSITIVE_ACCOUNT,
            "autoquant.correlation.sha256": "a" * 64,
            "autoquant.environment": SENTRY_OTLP_ENVIRONMENT,
            "autoquant.stage": "target",
            "autoquant.target.id": SENSITIVE_FACT,
            "autoquant.target.sha256": "b" * 64,
            "autoquant.trace.contract": TRADING_TRACE_CONTRACT_VERSION,
            "db.statement": SENSITIVE_EVENT,
            "autoquant.secret.sha256": "c" * 64,
        },
    ) as span:
        span.add_event(SENSITIVE_EVENT, {"raw.account": SENSITIVE_ACCOUNT})
        span.set_status(Status(StatusCode.ERROR, SENSITIVE_EVENT))

    assert len(inner.batches) == 1
    exported = inner.batches[0][0]
    assert exported.name == "autoquant.target"
    assert dict(exported.attributes or {}) == {
        "autoquant.correlation.sha256": "a" * 64,
        "autoquant.environment": SENTRY_OTLP_ENVIRONMENT,
        "autoquant.stage": "target",
        "autoquant.target.sha256": "b" * 64,
        "autoquant.trace.contract": TRADING_TRACE_CONTRACT_VERSION,
    }
    assert dict(exported.resource.attributes) == {
        "autoquant.telemetry.mode": "diagnostic_only",
        "deployment.environment": SENTRY_OTLP_ENVIRONMENT,
        "deployment.environment.name": SENTRY_OTLP_ENVIRONMENT,
        "service.name": SENTRY_OTLP_SERVICE_NAME,
        "service.version": RELEASE,
    }
    assert exported.events == ()
    assert exported.links == ()
    assert exported.status.status_code is StatusCode.ERROR
    assert exported.status.description is None
    assert exported.instrumentation_scope is not None
    assert exported.instrumentation_scope.name == SENTRY_OTLP_SERVICE_NAME
    assert exported.instrumentation_scope.version == RELEASE
    assert exported.context is not None
    assert len(exported.context.trace_state) == 0

    rendered = repr(exported)
    for sensitive in (
        SENSITIVE_ACCOUNT,
        SENSITIVE_FACT,
        SENSITIVE_EVENT,
        "sensitive-hostname",
        "raw-command-and-secret",
        "sensitive-instrumentation-scope",
        "private-version",
    ):
        assert sensitive not in rendered
    provider.shutdown()


def test_exporter_fails_closed_on_resource_pin_mismatch_without_delegating() -> None:
    inner = CapturingExporter()
    exporter = SentryOtlpTraceExporter(configuration=_configuration(), inner=inner)
    mismatched = ReadableSpan(
        name="operation",
        resource=_pinned_resource(**{"service.version": "different-release"}),
        attributes={"autoquant.correlation.sha256": "a" * 64},
    )

    assert exporter.export((mismatched,)) is SpanExportResult.FAILURE
    assert inner.batches == []


def test_export_and_lifecycle_failures_are_sanitized_and_never_authorize_effects() -> None:
    failing_export = SentryOtlpTraceExporter(
        configuration=_configuration(),
        inner=CapturingExporter(fail_export=True),
    )
    span = ReadableSpan(
        name=SENSITIVE_FACT,
        resource=_pinned_resource(),
        attributes={"autoquant.correlation.sha256": "a" * 64},
    )
    assert failing_export.export((span,)) is SpanExportResult.FAILURE
    assert not failing_export.trading_effect_authorized
    assert not failing_export.broker_action_authorized

    inner = CapturingExporter(fail_shutdown=True)
    failing_shutdown = SentryOtlpTraceExporter(
        configuration=_configuration(),
        inner=inner,
    )
    with pytest.raises(SentryOtlpExporterError) as failure:
        failing_shutdown.shutdown()
    assert SENSITIVE_EVENT not in str(failure.value)
    assert PUBLIC_KEY not in repr(failure.value)


def test_force_flush_is_bounded_and_delegates_only_valid_timeouts() -> None:
    inner = CapturingExporter()
    exporter = SentryOtlpTraceExporter(configuration=_configuration(), inner=inner)

    assert not exporter.force_flush(0)
    assert not exporter.force_flush(-1)
    assert not exporter.force_flush(True)
    assert exporter.force_flush(2_500)
    assert inner.flush_timeouts == [2_500]
