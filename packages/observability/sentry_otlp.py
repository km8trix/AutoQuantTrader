"""Fixed, secret-safe Sentry OTLP/HTTP trace-export composition.

Sentry's official OTLP exporters derive both the trace endpoint and
``X-Sentry-Auth`` header from a project DSN.  This module follows that contract
for Sentry Cloud, while wrapping the generic OpenTelemetry exporter so only
diagnostic identities and SHA-256 evidence leave the process.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import cast
from urllib.parse import SplitResult, urlsplit, urlunsplit

import requests
from opentelemetry.exporter.otlp.proto.http import Compression
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.util.instrumentation import InstrumentationScope
from opentelemetry.trace import SpanContext, Status, TraceState

from packages.observability.tracing import (
    TRADING_TRACE_CONTRACT_VERSION,
    TradingTraceStage,
)

SENTRY_OTLP_PROVIDER_ID = "sentry-otlp-http-traces"
SENTRY_OTLP_SERVICE_NAME = "autoquant-trader"
SENTRY_OTLP_ENVIRONMENT = "paper"
SENTRY_OTLP_AUTH_API_VERSION = "7"
SENTRY_OTLP_CLIENT_ID = "autoquant-trader/0.1"
SENTRY_OTLP_EXPORT_TIMEOUT_SECONDS = 5.0

_SENTRY_CLOUD_HOST = re.compile(r"^o[1-9][0-9]*[.]ingest(?:[.][a-z0-9-]+)?[.]sentry[.]io$")
_SENTRY_PUBLIC_KEY = re.compile(r"^[0-9a-f]{32}$")
_SENTRY_PROJECT_PATH = re.compile(r"^/([1-9][0-9]{0,31})/?$")
_RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_SAFE_ATTRIBUTE_KEYS = frozenset(
    {
        "autoquant.correlation.sha256",
        "autoquant.environment",
        "autoquant.stage",
        "autoquant.trace.contract",
        *(f"autoquant.{stage.value}.sha256" for stage in TradingTraceStage),
    }
)
type OtlpExporterFactory = Callable[..., object]


class SentryOtlpConfigurationError(ValueError):
    """Sentry OTLP composition is incomplete or violates a fixed pin."""


class SentryOtlpExporterError(RuntimeError):
    """A sanitized exporter lifecycle failure."""


@dataclass(frozen=True, slots=True)
class SentryOtlpConfiguration:
    """Runtime-only DSN plus nonsecret immutable deployment pins."""

    dsn: str = field(repr=False)
    release: str
    service_name: str = SENTRY_OTLP_SERVICE_NAME
    environment: str = SENTRY_OTLP_ENVIRONMENT

    def __post_init__(self) -> None:
        _validate_configuration(self)

    def __repr__(self) -> str:
        return (
            "SentryOtlpConfiguration("
            f"release={self.release!r}, "
            f"service_name={self.service_name!r}, "
            f"environment={self.environment!r}, "
            "dsn='[REDACTED]')"
        )


class SentryOtlpTraceExporter(SpanExporter):
    """Sanitize spans, enforce resource pins, then delegate to OTLP/HTTP."""

    __slots__ = ("_configuration", "_inner", "_safe_resource", "_scope")

    def __init__(
        self,
        *,
        configuration: SentryOtlpConfiguration,
        inner: SpanExporter,
    ) -> None:
        if type(configuration) is not SentryOtlpConfiguration:
            raise SentryOtlpConfigurationError("Sentry OTLP requires an exact configuration")
        configuration.__post_init__()
        if not isinstance(inner, SpanExporter):
            raise SentryOtlpConfigurationError(
                "Sentry OTLP requires an OpenTelemetry span exporter"
            )
        self._configuration = configuration
        self._inner = inner
        self._safe_resource = Resource(
            {
                "autoquant.telemetry.mode": "diagnostic_only",
                "deployment.environment": configuration.environment,
                "deployment.environment.name": configuration.environment,
                "service.name": configuration.service_name,
                "service.version": configuration.release,
            }
        )
        self._scope = InstrumentationScope(
            name=SENTRY_OTLP_SERVICE_NAME,
            version=configuration.release,
        )

    @property
    def provider_id(self) -> str:
        return SENTRY_OTLP_PROVIDER_ID

    @property
    def diagnostic_only(self) -> bool:
        return True

    @property
    def trading_effect_authorized(self) -> bool:
        return False

    @property
    def broker_action_authorized(self) -> bool:
        return False

    def __repr__(self) -> str:
        return (
            "SentryOtlpTraceExporter("
            f"provider_id={self.provider_id!r}, "
            "diagnostic_only=True, credentials='[REDACTED]')"
        )

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        sanitized: list[ReadableSpan] = []
        for span in spans:
            cleaned = self._sanitize(span)
            if cleaned is None:
                return SpanExportResult.FAILURE
            sanitized.append(cleaned)
        if not sanitized:
            return SpanExportResult.SUCCESS
        try:
            result = self._inner.export(tuple(sanitized))
        except Exception:
            return SpanExportResult.FAILURE
        if type(result) is not SpanExportResult:
            return SpanExportResult.FAILURE
        return result

    def shutdown(self) -> None:
        try:
            self._inner.shutdown()
        except Exception:
            raise SentryOtlpExporterError("Sentry OTLP exporter shutdown failed") from None

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        if type(timeout_millis) is not int or isinstance(timeout_millis, bool):
            return False
        if timeout_millis <= 0:
            return False
        try:
            result = self._inner.force_flush(timeout_millis)
        except Exception:
            return False
        # The official OTLP/HTTP exporter exports synchronously and inherits
        # SpanExporter's no-op force_flush, whose return is None.
        return True if result is None else result is True

    def _sanitize(self, span: object) -> ReadableSpan | None:
        if not isinstance(span, ReadableSpan):
            return None
        resource = span.resource.attributes
        if (
            resource.get("service.name") != self._configuration.service_name
            or resource.get("service.version") != self._configuration.release
            or resource.get("deployment.environment.name") != self._configuration.environment
        ):
            return None

        source_attributes = span.attributes
        attributes: dict[str, str] = {}
        if source_attributes is not None:
            for key, value in source_attributes.items():
                if key not in _SAFE_ATTRIBUTE_KEYS or type(value) is not str:
                    continue
                if key.endswith(".sha256"):
                    if _SHA256.fullmatch(value) is not None:
                        attributes[key] = value
                elif key == "autoquant.environment":
                    if value == self._configuration.environment:
                        attributes[key] = value
                elif key == "autoquant.stage":
                    if value in {stage.value for stage in TradingTraceStage}:
                        attributes[key] = value
                elif key == "autoquant.trace.contract" and value == TRADING_TRACE_CONTRACT_VERSION:
                    attributes[key] = value

        stage = attributes.get("autoquant.stage")
        name = "autoquant.diagnostic" if stage is None else f"autoquant.{stage}"
        return ReadableSpan(
            name=name,
            context=_sanitized_context(span.context),
            parent=_sanitized_context(span.parent),
            resource=self._safe_resource,
            attributes=attributes,
            events=(),
            links=(),
            kind=span.kind,
            status=Status(span.status.status_code),
            start_time=span.start_time,
            end_time=span.end_time,
            instrumentation_scope=self._scope,
        )


def _validate_configuration(configuration: SentryOtlpConfiguration) -> None:
    if (
        type(configuration.dsn) is not str
        or type(configuration.release) is not str
        or _RELEASE.fullmatch(configuration.release) is None
        or configuration.service_name != SENTRY_OTLP_SERVICE_NAME
        or configuration.environment != SENTRY_OTLP_ENVIRONMENT
    ):
        raise SentryOtlpConfigurationError("Sentry OTLP configuration is invalid")
    _parse_sentry_cloud_dsn(configuration.dsn)


def _parse_sentry_cloud_dsn(dsn: str) -> tuple[SplitResult, str, str]:
    try:
        parsed = urlsplit(dsn)
        host = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        raise SentryOtlpConfigurationError("Sentry OTLP DSN is invalid") from None
    project_match = _SENTRY_PROJECT_PATH.fullmatch(parsed.path)
    if (
        parsed.scheme != "https"
        or host is None
        or _SENTRY_CLOUD_HOST.fullmatch(host) is None
        or port is not None
        or type(parsed.username) is not str
        or _SENTRY_PUBLIC_KEY.fullmatch(parsed.username) is None
        or parsed.password is not None
        or project_match is None
        or parsed.query
        or parsed.fragment
    ):
        raise SentryOtlpConfigurationError("Sentry OTLP DSN is invalid")
    return parsed, project_match.group(1), parsed.username


def _sanitized_context(context: SpanContext | None) -> SpanContext | None:
    if context is None:
        return None
    return SpanContext(
        trace_id=context.trace_id,
        span_id=context.span_id,
        is_remote=context.is_remote,
        trace_flags=context.trace_flags,
        trace_state=TraceState(),
    )


def build_sentry_otlp_trace_exporter(
    configuration: SentryOtlpConfiguration,
    *,
    exporter_factory: OtlpExporterFactory = OTLPSpanExporter,
) -> SentryOtlpTraceExporter:
    """Build a diagnostic-only Sentry Cloud OTLP/HTTP trace exporter."""

    if type(configuration) is not SentryOtlpConfiguration:
        raise SentryOtlpConfigurationError("Sentry OTLP requires an exact configuration")
    configuration.__post_init__()
    if not callable(exporter_factory):
        raise SentryOtlpConfigurationError("Sentry OTLP exporter factory is invalid")
    parsed, project_id, public_key = _parse_sentry_cloud_dsn(configuration.dsn)
    endpoint = urlunsplit(
        (
            "https",
            cast(str, parsed.hostname),
            f"/api/{project_id}/integration/otlp/v1/traces/",
            "",
            "",
        )
    )
    auth = (
        "Sentry "
        f"sentry_version={SENTRY_OTLP_AUTH_API_VERSION}, "
        f"sentry_client={SENTRY_OTLP_CLIENT_ID}, "
        f"sentry_key={public_key}"
    )
    session = requests.Session()
    session.trust_env = False
    try:
        inner = exporter_factory(
            endpoint=endpoint,
            # The upstream annotation accepts only a CA-bundle path, although
            # its implementation and Requests also accept exact True for the
            # system trust store. Supplying it explicitly prevents an ambient
            # OTEL_* certificate variable from replacing verification policy.
            certificate_file=cast(str, True),
            headers={"X-Sentry-Auth": auth},
            timeout=SENTRY_OTLP_EXPORT_TIMEOUT_SECONDS,
            compression=Compression.NoCompression,
            session=session,
        )
    except Exception:
        session.close()
        raise SentryOtlpConfigurationError("Sentry OTLP exporter construction failed") from None
    if not isinstance(inner, SpanExporter):
        session.close()
        raise SentryOtlpConfigurationError(
            "Sentry OTLP exporter factory returned an invalid exporter"
        )
    return SentryOtlpTraceExporter(configuration=configuration, inner=inner)


def _require_fixed_constants() -> None:
    if (
        not math.isfinite(SENTRY_OTLP_EXPORT_TIMEOUT_SECONDS)
        or SENTRY_OTLP_EXPORT_TIMEOUT_SECONDS <= 0
    ):
        raise RuntimeError("Sentry OTLP fixed constants are invalid")


_require_fixed_constants()
