"""Pure fail-closed readiness contract for the recommended paper deployment.

The contract records only opaque provider identities, secret *references*, and
content digests.  It never accepts a database URL, DSN, API key, routing key,
phone number, or other secret value.  Readiness means only that the pinned
no-exposure smoke deployment has complete evidence; it never grants trading,
new-exposure, public-ingress, or automatic-rearm authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum

from packages.application.no_exposure_smoke_strategy import (
    NO_EXPOSURE_SMOKE_ARTIFACT_SHA256,
    NO_EXPOSURE_SMOKE_CONFIGURATION_SHA256,
    NO_EXPOSURE_SMOKE_MANIFEST_SHA256,
    NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION,
    NO_EXPOSURE_SMOKE_STRATEGY_ID,
    NO_EXPOSURE_SMOKE_STRATEGY_VERSION,
)
from packages.domain.canonical import canonical_json_text
from packages.domain.identifiers import canonical_id

PAPER_DEPLOYMENT_CONTRACT_VERSION = "phase5-paper-deployment-readiness-v2"

_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SECRET_REFERENCE = re.compile(r"^secret://paper/[A-Za-z0-9][A-Za-z0-9._:/-]{0,241}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PaperDeploymentError(ValueError):
    """A deployment decision, source pin, or evidence item is malformed."""


class PaperDeploymentConflict(PaperDeploymentError):
    """Deployment evidence crosses immutable providers, sources, or revisions."""


class PaperDeploymentEnvironment(StrEnum):
    PAPER = "paper"
    LIVE = "live"


class PaperDeploymentNetworkMode(StrEnum):
    PRIVATE_OUTBOUND_ONLY = "private_outbound_only"
    PUBLIC_INBOUND = "public_inbound"


class PaperDatabaseProvider(StrEnum):
    SUPABASE_MANAGED_POSTGRESQL = "supabase_managed_postgresql"
    OTHER = "other"


class PaperDatabasePlan(StrEnum):
    SUPABASE_FREE = "supabase_free"
    OTHER = "other"


class PaperWorkerProvider(StrEnum):
    LOCAL_OWNER_SUPERVISED = "local_owner_supervised"
    RENDER_PRIVATE_WORKER = "render_private_worker"
    OTHER = "other"


class PaperBrokerMode(StrEnum):
    ALPACA_PAPER = "alpaca_paper"
    ALPACA_LIVE = "alpaca_live"


class PaperTelemetryProvider(StrEnum):
    SENTRY = "sentry"
    OTHER = "other"


class PaperAlertProvider(StrEnum):
    DEFERRED = "deferred"
    PAGERDUTY = "pagerduty"
    TWILIO_SMS = "twilio_sms"
    OTHER = "other"


class PaperSecretPurpose(StrEnum):
    DATABASE = "database"
    BROKER = "broker"
    TELEMETRY = "telemetry"
    PRIMARY_ALERT = "primary_alert"
    FALLBACK_ALERT = "fallback_alert"


class PaperSourceKind(StrEnum):
    DEPLOYMENT_SPEC = "deployment_spec"
    RUNTIME_IMAGE = "runtime_image"
    ALERT_ROUTE_PLAN = "alert_route_plan"
    STRATEGY_ARTIFACT = "strategy_artifact"
    STRATEGY_MANIFEST = "strategy_manifest"
    RISK_POLICY = "risk_policy"
    FILL_CORRECTION_POLICY = "fill_correction_policy"
    RECONCILIATION_POLICY = "reconciliation_policy"
    TRUSTED_TIME_POLICY = "trusted_time_policy"
    MANUAL_REARM_POLICY = "manual_rearm_policy"
    CONTROL_ALERT_POLICY = "control_alert_policy"
    HEARTBEAT_WATCHDOG_SPEC = "heartbeat_watchdog_spec"
    DEPLOYED_DRILL_PLAN = "deployed_drill_plan"


class PaperDeploymentBlocker(StrEnum):
    """Canonical reasons the recommended no-exposure deployment is not ready."""

    ENVIRONMENT_NOT_PAPER = "environment_not_paper"
    LIVE_BROKER_SELECTED = "live_broker_selected"
    PUBLIC_INBOUND_ENABLED = "public_inbound_enabled"
    DATABASE_PROVIDER_NOT_RECOMMENDED = "database_provider_not_recommended"
    DATABASE_PLAN_NOT_SUPABASE_FREE = "database_plan_not_supabase_free"
    WORKER_PROVIDER_NOT_LOCAL_OWNER_SUPERVISED = "worker_provider_not_local_owner_supervised"
    TELEMETRY_PROVIDER_NOT_RECOMMENDED = "telemetry_provider_not_recommended"
    ALERT_PROVIDER_NOT_DEFERRED = "alert_provider_not_deferred"
    STRATEGY_PIN_MISMATCH = "strategy_pin_mismatch"
    DATABASE_SECRET_SOURCE_MISSING = "database_secret_source_missing"
    BROKER_SECRET_SOURCE_MISSING = "broker_secret_source_missing"
    TELEMETRY_SECRET_SOURCE_MISSING = "telemetry_secret_source_missing"
    PRIMARY_ALERT_SECRET_SOURCE_MISSING = "primary_alert_secret_source_missing"
    FALLBACK_ALERT_SECRET_SOURCE_MISSING = "fallback_alert_secret_source_missing"
    DEPLOYMENT_SPEC_SOURCE_MISSING = "deployment_spec_source_missing"
    RUNTIME_IMAGE_SOURCE_MISSING = "runtime_image_source_missing"
    ALERT_ROUTE_SOURCE_MISSING = "alert_route_source_missing"
    STRATEGY_ARTIFACT_SOURCE_MISSING = "strategy_artifact_source_missing"
    STRATEGY_MANIFEST_SOURCE_MISSING = "strategy_manifest_source_missing"
    STRATEGY_ARTIFACT_SOURCE_MISMATCH = "strategy_artifact_source_mismatch"
    STRATEGY_MANIFEST_SOURCE_MISMATCH = "strategy_manifest_source_mismatch"
    PROVIDER_INDEPENDENCE_EVIDENCE_MISSING = "provider_independence_evidence_missing"
    PROVIDER_INDEPENDENCE_BINDING_MISMATCH = "provider_independence_binding_mismatch"
    PROVIDER_INDEPENDENCE_UNVERIFIED = "provider_independence_unverified"
    RISK_POLICY_SOURCE_MISSING = "risk_policy_source_missing"
    AUTHORITATIVE_RISK_EVIDENCE_MISSING = "authoritative_risk_evidence_missing"
    AUTHORITATIVE_RISK_BINDING_MISMATCH = "authoritative_risk_binding_mismatch"
    AUTHORITATIVE_RISK_UNVERIFIED = "authoritative_risk_unverified"
    FILL_CORRECTION_SOURCE_MISSING = "fill_correction_source_missing"
    CORRECTION_SAFE_FILL_EVIDENCE_MISSING = "correction_safe_fill_evidence_missing"
    CORRECTION_SAFE_FILL_BINDING_MISMATCH = "correction_safe_fill_binding_mismatch"
    CORRECTION_SAFE_FILL_UNVERIFIED = "correction_safe_fill_unverified"
    RECONCILIATION_SOURCE_MISSING = "reconciliation_source_missing"
    QUALIFIED_RECONCILIATION_EVIDENCE_MISSING = "qualified_reconciliation_evidence_missing"
    QUALIFIED_RECONCILIATION_BINDING_MISMATCH = "qualified_reconciliation_binding_mismatch"
    QUALIFIED_RECONCILIATION_UNVERIFIED = "qualified_reconciliation_unverified"
    TRUSTED_TIME_SOURCE_MISSING = "trusted_time_source_missing"
    MANUAL_REARM_SOURCE_MISSING = "manual_rearm_source_missing"
    TRUSTED_TIME_REARM_EVIDENCE_MISSING = "trusted_time_rearm_evidence_missing"
    TRUSTED_TIME_REARM_BINDING_MISMATCH = "trusted_time_rearm_binding_mismatch"
    TRUSTED_TIME_REARM_UNVERIFIED = "trusted_time_rearm_unverified"
    CONTROL_ALERT_POLICY_SOURCE_MISSING = "control_alert_policy_source_missing"
    FIXED_PAUSED_CONTROL_ALERT_EVIDENCE_MISSING = "fixed_paused_control_alert_evidence_missing"
    FIXED_PAUSED_CONTROL_ALERT_BINDING_MISMATCH = "fixed_paused_control_alert_binding_mismatch"
    FIXED_PAUSED_CONTROL_ALERT_UNVERIFIED = "fixed_paused_control_alert_unverified"
    HEARTBEAT_WATCHDOG_SOURCE_MISSING = "heartbeat_watchdog_source_missing"
    EXTERNAL_HEARTBEAT_EVIDENCE_MISSING = "external_heartbeat_evidence_missing"
    EXTERNAL_HEARTBEAT_BINDING_MISMATCH = "external_heartbeat_binding_mismatch"
    EXTERNAL_HEARTBEAT_UNVERIFIED = "external_heartbeat_unverified"
    DEPLOYED_DRILL_PLAN_SOURCE_MISSING = "deployed_drill_plan_source_missing"
    DEPLOYED_DRILL_EVIDENCE_MISSING = "deployed_drill_evidence_missing"
    DEPLOYED_DRILL_BINDING_MISMATCH = "deployed_drill_binding_mismatch"
    DEPLOYED_DRILL_FAILED = "deployed_drill_failed"
    LOCAL_OWNER_SUPERVISION_ONLY = "local_owner_supervision_only"
    EXTERNAL_ALERTS_DEFERRED = "external_alerts_deferred"


PAPER_DEPLOYMENT_BLOCKER_ORDER = tuple(PaperDeploymentBlocker)
_BLOCKER_ORDER = {blocker: index for index, blocker in enumerate(PAPER_DEPLOYMENT_BLOCKER_ORDER)}
PAPER_SMOKE_DEPLOYMENT_BLOCKERS = frozenset(
    {
        PaperDeploymentBlocker.ENVIRONMENT_NOT_PAPER,
        PaperDeploymentBlocker.LIVE_BROKER_SELECTED,
        PaperDeploymentBlocker.PUBLIC_INBOUND_ENABLED,
        PaperDeploymentBlocker.DATABASE_PROVIDER_NOT_RECOMMENDED,
        PaperDeploymentBlocker.DATABASE_PLAN_NOT_SUPABASE_FREE,
        PaperDeploymentBlocker.WORKER_PROVIDER_NOT_LOCAL_OWNER_SUPERVISED,
        PaperDeploymentBlocker.TELEMETRY_PROVIDER_NOT_RECOMMENDED,
        PaperDeploymentBlocker.ALERT_PROVIDER_NOT_DEFERRED,
        PaperDeploymentBlocker.STRATEGY_PIN_MISMATCH,
        PaperDeploymentBlocker.DATABASE_SECRET_SOURCE_MISSING,
        PaperDeploymentBlocker.TELEMETRY_SECRET_SOURCE_MISSING,
        PaperDeploymentBlocker.DEPLOYMENT_SPEC_SOURCE_MISSING,
        PaperDeploymentBlocker.RUNTIME_IMAGE_SOURCE_MISSING,
        PaperDeploymentBlocker.STRATEGY_ARTIFACT_SOURCE_MISSING,
        PaperDeploymentBlocker.STRATEGY_MANIFEST_SOURCE_MISSING,
        PaperDeploymentBlocker.STRATEGY_ARTIFACT_SOURCE_MISMATCH,
        PaperDeploymentBlocker.STRATEGY_MANIFEST_SOURCE_MISMATCH,
    }
)


def _require_safe_text(value: str, field_name: str) -> None:
    if type(value) is not str or _SAFE_TEXT.fullmatch(value) is None:
        raise PaperDeploymentError(f"{field_name} must contain 1-128 safe visible characters")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise PaperDeploymentError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_exact_enum(value: object, enum_type: type[StrEnum], field_name: str) -> None:
    if type(value) is not enum_type:
        raise PaperDeploymentError(f"{field_name} must be an exact {enum_type.__name__}")


def _require_exact_bool(value: object, field_name: str) -> None:
    if type(value) is not bool:
        raise PaperDeploymentError(f"{field_name} must be exact bool")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class OpaqueSecretReference:
    """A versioned secret-manager reference that cannot carry a secret value."""

    purpose: PaperSecretPurpose
    reference_id: str = field(repr=False)
    version_id: str = field(repr=False)

    def __post_init__(self) -> None:
        _require_exact_enum(
            self.purpose,
            PaperSecretPurpose,
            "paper deployment secret purpose",
        )
        if (
            type(self.reference_id) is not str
            or _SECRET_REFERENCE.fullmatch(self.reference_id) is None
        ):
            raise PaperDeploymentError(
                "paper deployment secret reference must be a bounded secret://paper/ reference"
            )
        _require_safe_text(self.version_id, "paper deployment secret reference version")

    @property
    def reference_sha256(self) -> str:
        return _sha256(self.reference_id)

    @property
    def version_sha256(self) -> str:
        return _sha256(self.version_id)

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "secret_reference",
                self.purpose,
                self.reference_sha256,
                self.version_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


@dataclass(frozen=True, slots=True)
class AuthoritativeSourcePin:
    """One nonsecret authoritative source identity and exact content digest."""

    kind: PaperSourceKind
    source_id: str
    revision_id: str
    content_sha256: str

    def __post_init__(self) -> None:
        _require_exact_enum(self.kind, PaperSourceKind, "paper deployment source kind")
        _require_safe_text(self.source_id, "paper deployment source ID")
        _require_safe_text(self.revision_id, "paper deployment source revision")
        _require_sha256(self.content_sha256, "paper deployment source content_sha256")

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "source_pin",
                self.kind,
                self.source_id,
                self.revision_id,
                self.content_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


@dataclass(frozen=True, slots=True)
class PinnedNoExposureStrategy:
    """Exact immutable pins for the repository-owned no-exposure artifact."""

    strategy_id: str
    strategy_version: str
    result_contract_version: str
    configuration_sha256: str
    artifact_sha256: str
    manifest_sha256: str

    @classmethod
    def recommended(cls) -> PinnedNoExposureStrategy:
        return cls(
            strategy_id=NO_EXPOSURE_SMOKE_STRATEGY_ID,
            strategy_version=NO_EXPOSURE_SMOKE_STRATEGY_VERSION,
            result_contract_version=NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION,
            configuration_sha256=NO_EXPOSURE_SMOKE_CONFIGURATION_SHA256,
            artifact_sha256=NO_EXPOSURE_SMOKE_ARTIFACT_SHA256,
            manifest_sha256=NO_EXPOSURE_SMOKE_MANIFEST_SHA256,
        )

    def __post_init__(self) -> None:
        _require_safe_text(self.strategy_id, "paper deployment strategy ID")
        _require_safe_text(self.strategy_version, "paper deployment strategy version")
        _require_safe_text(
            self.result_contract_version,
            "paper deployment strategy result-contract version",
        )
        _require_sha256(
            self.configuration_sha256,
            "paper deployment strategy configuration_sha256",
        )
        _require_sha256(self.artifact_sha256, "paper deployment strategy artifact_sha256")
        _require_sha256(self.manifest_sha256, "paper deployment strategy manifest_sha256")

    @property
    def matches_recommendation(self) -> bool:
        return self == type(self).recommended()

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "strategy_pin",
                self.strategy_id,
                self.strategy_version,
                self.result_contract_version,
                self.configuration_sha256,
                self.artifact_sha256,
                self.manifest_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


@dataclass(frozen=True, slots=True)
class RecommendedPaperDeployment:
    """The selected provider stack and immutable no-exposure strategy decision."""

    deployment_id: str
    revision_id: str
    environment: PaperDeploymentEnvironment
    network_mode: PaperDeploymentNetworkMode
    database_provider: PaperDatabaseProvider
    database_plan: PaperDatabasePlan
    worker_provider: PaperWorkerProvider
    broker_mode: PaperBrokerMode
    telemetry_provider: PaperTelemetryProvider
    primary_alert_provider: PaperAlertProvider
    fallback_alert_provider: PaperAlertProvider
    strategy: PinnedNoExposureStrategy

    @classmethod
    def create(cls, *, deployment_id: str, revision_id: str) -> RecommendedPaperDeployment:
        return cls(
            deployment_id=deployment_id,
            revision_id=revision_id,
            environment=PaperDeploymentEnvironment.PAPER,
            network_mode=PaperDeploymentNetworkMode.PRIVATE_OUTBOUND_ONLY,
            database_provider=PaperDatabaseProvider.SUPABASE_MANAGED_POSTGRESQL,
            database_plan=PaperDatabasePlan.SUPABASE_FREE,
            worker_provider=PaperWorkerProvider.LOCAL_OWNER_SUPERVISED,
            broker_mode=PaperBrokerMode.ALPACA_PAPER,
            telemetry_provider=PaperTelemetryProvider.SENTRY,
            primary_alert_provider=PaperAlertProvider.DEFERRED,
            fallback_alert_provider=PaperAlertProvider.DEFERRED,
            strategy=PinnedNoExposureStrategy.recommended(),
        )

    def __post_init__(self) -> None:
        _require_safe_text(self.deployment_id, "paper deployment ID")
        _require_safe_text(self.revision_id, "paper deployment revision")
        _require_exact_enum(
            self.environment,
            PaperDeploymentEnvironment,
            "paper deployment environment",
        )
        _require_exact_enum(
            self.network_mode,
            PaperDeploymentNetworkMode,
            "paper deployment network mode",
        )
        _require_exact_enum(
            self.database_provider,
            PaperDatabaseProvider,
            "paper deployment database provider",
        )
        _require_exact_enum(
            self.database_plan,
            PaperDatabasePlan,
            "paper deployment database plan",
        )
        _require_exact_enum(
            self.worker_provider,
            PaperWorkerProvider,
            "paper deployment worker provider",
        )
        _require_exact_enum(
            self.broker_mode,
            PaperBrokerMode,
            "paper deployment broker mode",
        )
        _require_exact_enum(
            self.telemetry_provider,
            PaperTelemetryProvider,
            "paper deployment telemetry provider",
        )
        _require_exact_enum(
            self.primary_alert_provider,
            PaperAlertProvider,
            "paper deployment primary alert provider",
        )
        _require_exact_enum(
            self.fallback_alert_provider,
            PaperAlertProvider,
            "paper deployment fallback alert provider",
        )
        if type(self.strategy) is not PinnedNoExposureStrategy:
            raise PaperDeploymentError(
                "paper deployment requires an exact PinnedNoExposureStrategy"
            )
        self.strategy.__post_init__()

    @property
    def deployment_key(self) -> str:
        return canonical_id(
            "recommended-paper-deployment",
            self.deployment_id,
            self.revision_id,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "deployment_decision",
                self.deployment_key,
                self.deployment_id,
                self.revision_id,
                self.environment,
                self.network_mode,
                self.database_provider,
                self.database_plan,
                self.worker_provider,
                self.broker_mode,
                self.telemetry_provider,
                self.primary_alert_provider,
                self.fallback_alert_provider,
                self.strategy.semantic_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)

    @property
    def broker_action_authorized(self) -> bool:
        return False

    @property
    def new_exposure_authorized(self) -> bool:
        return False

    @property
    def live_trading_authorized(self) -> bool:
        return False

    @property
    def public_inbound_authorized(self) -> bool:
        return False


_SECRET_FIELDS = (
    ("database_credentials", PaperSecretPurpose.DATABASE),
    ("broker_credentials", PaperSecretPurpose.BROKER),
    ("telemetry_credentials", PaperSecretPurpose.TELEMETRY),
    ("primary_alert_credentials", PaperSecretPurpose.PRIMARY_ALERT),
    ("fallback_alert_credentials", PaperSecretPurpose.FALLBACK_ALERT),
)
_SOURCE_FIELDS = (
    ("deployment_spec", PaperSourceKind.DEPLOYMENT_SPEC),
    ("runtime_image", PaperSourceKind.RUNTIME_IMAGE),
    ("alert_route_plan", PaperSourceKind.ALERT_ROUTE_PLAN),
    ("strategy_artifact", PaperSourceKind.STRATEGY_ARTIFACT),
    ("strategy_manifest", PaperSourceKind.STRATEGY_MANIFEST),
    ("risk_policy", PaperSourceKind.RISK_POLICY),
    ("fill_correction_policy", PaperSourceKind.FILL_CORRECTION_POLICY),
    ("reconciliation_policy", PaperSourceKind.RECONCILIATION_POLICY),
    ("trusted_time_policy", PaperSourceKind.TRUSTED_TIME_POLICY),
    ("manual_rearm_policy", PaperSourceKind.MANUAL_REARM_POLICY),
    ("control_alert_policy", PaperSourceKind.CONTROL_ALERT_POLICY),
    ("heartbeat_watchdog_spec", PaperSourceKind.HEARTBEAT_WATCHDOG_SPEC),
    ("deployed_drill_plan", PaperSourceKind.DEPLOYED_DRILL_PLAN),
)


@dataclass(frozen=True, slots=True)
class PaperDeploymentAuthoritativeSources:
    """All authoritative source references required by the fixed profile."""

    database_credentials: OpaqueSecretReference | None = None
    broker_credentials: OpaqueSecretReference | None = None
    telemetry_credentials: OpaqueSecretReference | None = None
    primary_alert_credentials: OpaqueSecretReference | None = None
    fallback_alert_credentials: OpaqueSecretReference | None = None
    deployment_spec: AuthoritativeSourcePin | None = None
    runtime_image: AuthoritativeSourcePin | None = None
    alert_route_plan: AuthoritativeSourcePin | None = None
    strategy_artifact: AuthoritativeSourcePin | None = None
    strategy_manifest: AuthoritativeSourcePin | None = None
    risk_policy: AuthoritativeSourcePin | None = None
    fill_correction_policy: AuthoritativeSourcePin | None = None
    reconciliation_policy: AuthoritativeSourcePin | None = None
    trusted_time_policy: AuthoritativeSourcePin | None = None
    manual_rearm_policy: AuthoritativeSourcePin | None = None
    control_alert_policy: AuthoritativeSourcePin | None = None
    heartbeat_watchdog_spec: AuthoritativeSourcePin | None = None
    deployed_drill_plan: AuthoritativeSourcePin | None = None

    def __post_init__(self) -> None:
        for field_name, purpose in _SECRET_FIELDS:
            reference = getattr(self, field_name)
            if reference is None:
                continue
            if type(reference) is not OpaqueSecretReference:
                raise PaperDeploymentError(
                    f"paper deployment {field_name} must be an exact secret reference"
                )
            reference.__post_init__()
            if reference.purpose is not purpose:
                raise PaperDeploymentConflict(
                    f"paper deployment {field_name} has the wrong secret purpose"
                )
        for field_name, kind in _SOURCE_FIELDS:
            source = getattr(self, field_name)
            if source is None:
                continue
            if type(source) is not AuthoritativeSourcePin:
                raise PaperDeploymentError(
                    f"paper deployment {field_name} must be an exact source pin"
                )
            source.__post_init__()
            if source.kind is not kind:
                raise PaperDeploymentConflict(
                    f"paper deployment {field_name} has the wrong source kind"
                )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "authoritative_sources",
                tuple(
                    (
                        field_name,
                        None
                        if getattr(self, field_name) is None
                        else getattr(self, field_name).semantic_sha256,
                    )
                    for field_name, _purpose in _SECRET_FIELDS
                ),
                tuple(
                    (
                        field_name,
                        None
                        if getattr(self, field_name) is None
                        else getattr(self, field_name).semantic_sha256,
                    )
                    for field_name, _kind in _SOURCE_FIELDS
                ),
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


@dataclass(frozen=True, slots=True)
class AlertProviderIndependenceEvidence:
    """Deployed proof that PagerDuty and Twilio do not share a failure path."""

    primary_provider: PaperAlertProvider
    fallback_provider: PaperAlertProvider
    alert_route_plan_sha256: str
    primary_secret_reference_sha256: str
    fallback_secret_reference_sha256: str
    provider_accounts_distinct: bool
    credential_sources_distinct: bool
    delivery_transports_distinct: bool
    failure_domains_distinct: bool
    verified_in_deployed_environment: bool
    evidence_sha256: str

    def __post_init__(self) -> None:
        _require_exact_enum(
            self.primary_provider,
            PaperAlertProvider,
            "alert independence primary provider",
        )
        _require_exact_enum(
            self.fallback_provider,
            PaperAlertProvider,
            "alert independence fallback provider",
        )
        for value, field_name in (
            (self.alert_route_plan_sha256, "alert independence route-plan SHA-256"),
            (
                self.primary_secret_reference_sha256,
                "alert independence primary secret-reference SHA-256",
            ),
            (
                self.fallback_secret_reference_sha256,
                "alert independence fallback secret-reference SHA-256",
            ),
            (self.evidence_sha256, "alert independence evidence SHA-256"),
        ):
            _require_sha256(value, field_name)
        for bool_value, field_name in (
            (self.provider_accounts_distinct, "alert provider-account independence"),
            (self.credential_sources_distinct, "alert credential-source independence"),
            (self.delivery_transports_distinct, "alert delivery-transport independence"),
            (self.failure_domains_distinct, "alert failure-domain independence"),
            (
                self.verified_in_deployed_environment,
                "alert deployed-environment independence",
            ),
        ):
            _require_exact_bool(bool_value, field_name)

    @property
    def operationally_verified(self) -> bool:
        return (
            self.primary_provider is PaperAlertProvider.PAGERDUTY
            and self.fallback_provider is PaperAlertProvider.TWILIO_SMS
            and self.provider_accounts_distinct
            and self.credential_sources_distinct
            and self.delivery_transports_distinct
            and self.failure_domains_distinct
            and self.verified_in_deployed_environment
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "alert_provider_independence",
                self.primary_provider,
                self.fallback_provider,
                self.alert_route_plan_sha256,
                self.primary_secret_reference_sha256,
                self.fallback_secret_reference_sha256,
                self.provider_accounts_distinct,
                self.credential_sources_distinct,
                self.delivery_transports_distinct,
                self.failure_domains_distinct,
                self.verified_in_deployed_environment,
                self.evidence_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


@dataclass(frozen=True, slots=True)
class AuthoritativeRiskEvidence:
    """Deployed proof that the pinned moderate risk source is authoritative."""

    risk_policy_sha256: str
    moderate_risk_profile_activated: bool
    durable_authoritative_head_verified: bool
    caller_override_rejected: bool
    evidence_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(self.risk_policy_sha256, "authoritative risk policy SHA-256")
        _require_sha256(self.evidence_sha256, "authoritative risk evidence SHA-256")
        _require_exact_bool(
            self.moderate_risk_profile_activated,
            "moderate risk profile activation",
        )
        _require_exact_bool(
            self.durable_authoritative_head_verified,
            "durable authoritative risk head",
        )
        _require_exact_bool(self.caller_override_rejected, "risk caller-override rejection")

    @property
    def operationally_verified(self) -> bool:
        return (
            self.moderate_risk_profile_activated
            and self.durable_authoritative_head_verified
            and self.caller_override_rejected
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "authoritative_risk",
                self.risk_policy_sha256,
                self.moderate_risk_profile_activated,
                self.durable_authoritative_head_verified,
                self.caller_override_rejected,
                self.evidence_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


@dataclass(frozen=True, slots=True)
class CorrectionSafeFillEvidence:
    """Deployed proof that fills and later corrections remain authoritative."""

    fill_correction_policy_sha256: str
    durable_fill_ledger_verified: bool
    bust_replace_chain_verified: bool
    unresolved_correction_blocks_readiness: bool
    evidence_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(
            self.fill_correction_policy_sha256,
            "correction-safe fill policy SHA-256",
        )
        _require_sha256(self.evidence_sha256, "correction-safe fill evidence SHA-256")
        _require_exact_bool(self.durable_fill_ledger_verified, "durable fill ledger evidence")
        _require_exact_bool(self.bust_replace_chain_verified, "fill bust/replace evidence")
        _require_exact_bool(
            self.unresolved_correction_blocks_readiness,
            "unresolved fill-correction gate",
        )

    @property
    def operationally_verified(self) -> bool:
        return (
            self.durable_fill_ledger_verified
            and self.bust_replace_chain_verified
            and self.unresolved_correction_blocks_readiness
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "correction_safe_fills",
                self.fill_correction_policy_sha256,
                self.durable_fill_ledger_verified,
                self.bust_replace_chain_verified,
                self.unresolved_correction_blocks_readiness,
                self.evidence_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


@dataclass(frozen=True, slots=True)
class QualifiedReconciliationEvidence:
    """Deployed proof of qualified, correction-aware broker reconciliation."""

    reconciliation_policy_sha256: str
    orders_positions_activity_qualified: bool
    correction_safe_fills_consumed: bool
    zero_unresolved_differences: bool
    evidence_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(
            self.reconciliation_policy_sha256,
            "qualified reconciliation policy SHA-256",
        )
        _require_sha256(
            self.evidence_sha256,
            "qualified reconciliation evidence SHA-256",
        )
        _require_exact_bool(
            self.orders_positions_activity_qualified,
            "orders/positions/activity qualification",
        )
        _require_exact_bool(
            self.correction_safe_fills_consumed,
            "reconciliation correction-safe fill consumption",
        )
        _require_exact_bool(
            self.zero_unresolved_differences,
            "reconciliation unresolved-difference gate",
        )

    @property
    def operationally_verified(self) -> bool:
        return (
            self.orders_positions_activity_qualified
            and self.correction_safe_fills_consumed
            and self.zero_unresolved_differences
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "qualified_reconciliation",
                self.reconciliation_policy_sha256,
                self.orders_positions_activity_qualified,
                self.correction_safe_fills_consumed,
                self.zero_unresolved_differences,
                self.evidence_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


@dataclass(frozen=True, slots=True)
class TrustedTimeManualRearmEvidence:
    """Deployed proof of durable trusted time and manual-only re-arm."""

    trusted_time_policy_sha256: str
    manual_rearm_policy_sha256: str
    durable_trusted_time_healthy: bool
    rollback_staleness_trip_verified: bool
    automatic_rearm_disabled: bool
    manual_rearm_evidence_durable: bool
    evidence_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(
            self.trusted_time_policy_sha256,
            "trusted-time policy SHA-256",
        )
        _require_sha256(
            self.manual_rearm_policy_sha256,
            "manual-rearm policy SHA-256",
        )
        _require_sha256(
            self.evidence_sha256,
            "trusted-time/manual-rearm evidence SHA-256",
        )
        _require_exact_bool(
            self.durable_trusted_time_healthy,
            "durable trusted-time health",
        )
        _require_exact_bool(
            self.rollback_staleness_trip_verified,
            "trusted-time rollback/staleness trip",
        )
        _require_exact_bool(self.automatic_rearm_disabled, "automatic re-arm disablement")
        _require_exact_bool(
            self.manual_rearm_evidence_durable,
            "durable manual re-arm evidence",
        )

    @property
    def operationally_verified(self) -> bool:
        return (
            self.durable_trusted_time_healthy
            and self.rollback_staleness_trip_verified
            and self.automatic_rearm_disabled
            and self.manual_rearm_evidence_durable
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "trusted_time_manual_rearm",
                self.trusted_time_policy_sha256,
                self.manual_rearm_policy_sha256,
                self.durable_trusted_time_healthy,
                self.rollback_staleness_trip_verified,
                self.automatic_rearm_disabled,
                self.manual_rearm_evidence_durable,
                self.evidence_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


@dataclass(frozen=True, slots=True)
class FixedPausedControlAlertEvidence:
    """Deployed proof that activation remains PAUSED with alert policy active."""

    control_alert_policy_sha256: str
    alert_route_plan_sha256: str
    fixed_paused_state_observed: bool
    automatic_running_transition_disabled: bool
    control_trip_alert_policy_activated: bool
    primary_and_fallback_routes_verified: bool
    evidence_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(
            self.control_alert_policy_sha256,
            "fixed-PAUSED control/alert policy SHA-256",
        )
        _require_sha256(
            self.alert_route_plan_sha256,
            "fixed-PAUSED alert route-plan SHA-256",
        )
        _require_sha256(
            self.evidence_sha256,
            "fixed-PAUSED control/alert evidence SHA-256",
        )
        _require_exact_bool(
            self.fixed_paused_state_observed,
            "fixed-PAUSED state evidence",
        )
        _require_exact_bool(
            self.automatic_running_transition_disabled,
            "automatic RUNNING transition disablement",
        )
        _require_exact_bool(
            self.control_trip_alert_policy_activated,
            "control-trip alert policy activation",
        )
        _require_exact_bool(
            self.primary_and_fallback_routes_verified,
            "primary/fallback alert-route verification",
        )

    @property
    def operationally_verified(self) -> bool:
        return (
            self.fixed_paused_state_observed
            and self.automatic_running_transition_disabled
            and self.control_trip_alert_policy_activated
            and self.primary_and_fallback_routes_verified
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "fixed_paused_control_alert",
                self.control_alert_policy_sha256,
                self.alert_route_plan_sha256,
                self.fixed_paused_state_observed,
                self.automatic_running_transition_disabled,
                self.control_trip_alert_policy_activated,
                self.primary_and_fallback_routes_verified,
                self.evidence_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


@dataclass(frozen=True, slots=True)
class ExternalHeartbeatWatchdogEvidence:
    """Deployed proof that an external failure domain supervises heartbeats."""

    heartbeat_watchdog_spec_sha256: str
    external_failure_domain_verified: bool
    missed_heartbeat_trip_verified: bool
    critical_alert_delivery_verified: bool
    evidence_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(
            self.heartbeat_watchdog_spec_sha256,
            "external heartbeat-watchdog specification SHA-256",
        )
        _require_sha256(
            self.evidence_sha256,
            "external heartbeat-watchdog evidence SHA-256",
        )
        _require_exact_bool(
            self.external_failure_domain_verified,
            "external heartbeat failure-domain evidence",
        )
        _require_exact_bool(
            self.missed_heartbeat_trip_verified,
            "missed-heartbeat trip evidence",
        )
        _require_exact_bool(
            self.critical_alert_delivery_verified,
            "heartbeat critical-alert delivery evidence",
        )

    @property
    def operationally_verified(self) -> bool:
        return (
            self.external_failure_domain_verified
            and self.missed_heartbeat_trip_verified
            and self.critical_alert_delivery_verified
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "external_heartbeat_watchdog",
                self.heartbeat_watchdog_spec_sha256,
                self.external_failure_domain_verified,
                self.missed_heartbeat_trip_verified,
                self.critical_alert_delivery_verified,
                self.evidence_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


@dataclass(frozen=True, slots=True)
class DeployedPaperDrillEvidence:
    """Exact deployed drill binding for one immutable deployment revision."""

    deployment_id: str
    decision_sha256: str
    deployment_spec_sha256: str
    runtime_image_sha256: str
    deployed_drill_plan_sha256: str
    strategy_artifact_sha256: str
    strategy_manifest_sha256: str
    campaign_id: str
    deployed_environment_observed: bool
    all_required_scenarios_passed: bool
    timing_deadlines_met: bool
    no_new_exposure_observed: bool
    live_trading_disabled_observed: bool
    public_inbound_absent_observed: bool
    manual_rearm_only_observed: bool
    evidence_sha256: str

    def __post_init__(self) -> None:
        _require_safe_text(self.deployment_id, "deployed paper drill deployment ID")
        _require_safe_text(self.campaign_id, "deployed paper drill campaign ID")
        for value, field_name in (
            (self.decision_sha256, "deployed paper drill decision_sha256"),
            (self.deployment_spec_sha256, "deployed paper drill deployment_spec_sha256"),
            (self.runtime_image_sha256, "deployed paper drill runtime_image_sha256"),
            (
                self.deployed_drill_plan_sha256,
                "deployed paper drill plan_sha256",
            ),
            (
                self.strategy_artifact_sha256,
                "deployed paper drill strategy_artifact_sha256",
            ),
            (
                self.strategy_manifest_sha256,
                "deployed paper drill strategy_manifest_sha256",
            ),
            (self.evidence_sha256, "deployed paper drill evidence_sha256"),
        ):
            _require_sha256(value, field_name)
        for bool_value, field_name in (
            (self.deployed_environment_observed, "deployed paper drill environment evidence"),
            (self.all_required_scenarios_passed, "deployed paper drill scenario evidence"),
            (self.timing_deadlines_met, "deployed paper drill deadline evidence"),
            (self.no_new_exposure_observed, "deployed paper drill exposure evidence"),
            (
                self.live_trading_disabled_observed,
                "deployed paper drill live-trading evidence",
            ),
            (
                self.public_inbound_absent_observed,
                "deployed paper drill public-inbound evidence",
            ),
            (
                self.manual_rearm_only_observed,
                "deployed paper drill manual-rearm evidence",
            ),
        ):
            _require_exact_bool(bool_value, field_name)

    @property
    def safety_checks_passed(self) -> bool:
        return (
            self.deployed_environment_observed
            and self.all_required_scenarios_passed
            and self.timing_deadlines_met
            and self.no_new_exposure_observed
            and self.live_trading_disabled_observed
            and self.public_inbound_absent_observed
            and self.manual_rearm_only_observed
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "deployed_drill",
                self.deployment_id,
                self.decision_sha256,
                self.deployment_spec_sha256,
                self.runtime_image_sha256,
                self.deployed_drill_plan_sha256,
                self.strategy_artifact_sha256,
                self.strategy_manifest_sha256,
                self.campaign_id,
                self.deployed_environment_observed,
                self.all_required_scenarios_passed,
                self.timing_deadlines_met,
                self.no_new_exposure_observed,
                self.live_trading_disabled_observed,
                self.public_inbound_absent_observed,
                self.manual_rearm_only_observed,
                self.evidence_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


@dataclass(frozen=True, slots=True)
class PaperDeploymentEvidence:
    """Sanitized source and deployed evidence supplied to the pure assessor."""

    sources: PaperDeploymentAuthoritativeSources
    provider_independence: AlertProviderIndependenceEvidence | None = None
    authoritative_risk: AuthoritativeRiskEvidence | None = None
    correction_safe_fills: CorrectionSafeFillEvidence | None = None
    qualified_reconciliation: QualifiedReconciliationEvidence | None = None
    trusted_time_manual_rearm: TrustedTimeManualRearmEvidence | None = None
    fixed_paused_control_alert: FixedPausedControlAlertEvidence | None = None
    external_heartbeat_watchdog: ExternalHeartbeatWatchdogEvidence | None = None
    deployed_drill: DeployedPaperDrillEvidence | None = None

    def __post_init__(self) -> None:
        if type(self.sources) is not PaperDeploymentAuthoritativeSources:
            raise PaperDeploymentError(
                "paper deployment evidence requires exact authoritative sources"
            )
        self.sources.__post_init__()
        if self.provider_independence is not None:
            if type(self.provider_independence) is not AlertProviderIndependenceEvidence:
                raise PaperDeploymentError(
                    "paper deployment provider independence evidence has the wrong type"
                )
            self.provider_independence.__post_init__()
        optional_evidence = (
            ("authoritative_risk", AuthoritativeRiskEvidence),
            ("correction_safe_fills", CorrectionSafeFillEvidence),
            ("qualified_reconciliation", QualifiedReconciliationEvidence),
            ("trusted_time_manual_rearm", TrustedTimeManualRearmEvidence),
            ("fixed_paused_control_alert", FixedPausedControlAlertEvidence),
            ("external_heartbeat_watchdog", ExternalHeartbeatWatchdogEvidence),
        )
        for field_name, evidence_type in optional_evidence:
            value = getattr(self, field_name)
            if value is None:
                continue
            if type(value) is not evidence_type:
                raise PaperDeploymentError(
                    f"paper deployment {field_name} evidence has the wrong type"
                )
            value.__post_init__()
        if self.deployed_drill is not None:
            if type(self.deployed_drill) is not DeployedPaperDrillEvidence:
                raise PaperDeploymentError("paper deployment drill evidence has the wrong type")
            self.deployed_drill.__post_init__()

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PAPER_DEPLOYMENT_CONTRACT_VERSION,
                "evidence",
                self.sources.semantic_sha256,
                None
                if self.provider_independence is None
                else self.provider_independence.semantic_sha256,
                None
                if self.authoritative_risk is None
                else self.authoritative_risk.semantic_sha256,
                None
                if self.correction_safe_fills is None
                else self.correction_safe_fills.semantic_sha256,
                None
                if self.qualified_reconciliation is None
                else self.qualified_reconciliation.semantic_sha256,
                None
                if self.trusted_time_manual_rearm is None
                else self.trusted_time_manual_rearm.semantic_sha256,
                None
                if self.fixed_paused_control_alert is None
                else self.fixed_paused_control_alert.semantic_sha256,
                None
                if self.external_heartbeat_watchdog is None
                else self.external_heartbeat_watchdog.semantic_sha256,
                None if self.deployed_drill is None else self.deployed_drill.semantic_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self.canonical_json)


def _independence_binding_matches(
    evidence: AlertProviderIndependenceEvidence,
    sources: PaperDeploymentAuthoritativeSources,
) -> bool:
    if (
        sources.alert_route_plan is None
        or sources.primary_alert_credentials is None
        or sources.fallback_alert_credentials is None
    ):
        return False
    return (
        evidence.alert_route_plan_sha256 == sources.alert_route_plan.content_sha256
        and evidence.primary_secret_reference_sha256
        == sources.primary_alert_credentials.semantic_sha256
        and evidence.fallback_secret_reference_sha256
        == sources.fallback_alert_credentials.semantic_sha256
    )


def _source_binding_matches(
    evidence_source_sha256: str,
    source: AuthoritativeSourcePin | None,
) -> bool:
    return source is not None and evidence_source_sha256 == source.content_sha256


def _trusted_time_rearm_binding_matches(
    evidence: TrustedTimeManualRearmEvidence,
    sources: PaperDeploymentAuthoritativeSources,
) -> bool:
    return _source_binding_matches(
        evidence.trusted_time_policy_sha256,
        sources.trusted_time_policy,
    ) and _source_binding_matches(
        evidence.manual_rearm_policy_sha256,
        sources.manual_rearm_policy,
    )


def _fixed_paused_control_alert_binding_matches(
    evidence: FixedPausedControlAlertEvidence,
    sources: PaperDeploymentAuthoritativeSources,
) -> bool:
    return _source_binding_matches(
        evidence.control_alert_policy_sha256,
        sources.control_alert_policy,
    ) and _source_binding_matches(
        evidence.alert_route_plan_sha256,
        sources.alert_route_plan,
    )


def _drill_binding_matches(
    drill: DeployedPaperDrillEvidence,
    decision: RecommendedPaperDeployment,
    sources: PaperDeploymentAuthoritativeSources,
) -> bool:
    if (
        sources.deployment_spec is None
        or sources.runtime_image is None
        or sources.deployed_drill_plan is None
        or sources.strategy_artifact is None
        or sources.strategy_manifest is None
    ):
        return False
    return (
        drill.deployment_id == decision.deployment_id
        and drill.decision_sha256 == decision.semantic_sha256
        and drill.deployment_spec_sha256 == sources.deployment_spec.content_sha256
        and drill.runtime_image_sha256 == sources.runtime_image.content_sha256
        and drill.deployed_drill_plan_sha256 == sources.deployed_drill_plan.content_sha256
        and drill.strategy_artifact_sha256 == sources.strategy_artifact.content_sha256
        and drill.strategy_manifest_sha256 == sources.strategy_manifest.content_sha256
    )


def _readiness_material(
    *,
    decision_sha256: str,
    evidence_sha256: str,
    blockers: tuple[PaperDeploymentBlocker, ...],
) -> tuple[object, ...]:
    return (
        PAPER_DEPLOYMENT_CONTRACT_VERSION,
        "readiness_report",
        decision_sha256,
        evidence_sha256,
        blockers,
    )


@dataclass(frozen=True, slots=True)
class _PaperDeploymentReadinessSeal:
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class PaperDeploymentReadinessReport:
    """Deterministic, sealed result; readiness grants no broker authority."""

    decision_sha256: str
    evidence_sha256: str
    blockers: tuple[PaperDeploymentBlocker, ...]
    _seal: _PaperDeploymentReadinessSeal = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _require_sha256(self.decision_sha256, "paper readiness decision_sha256")
        _require_sha256(self.evidence_sha256, "paper readiness evidence_sha256")
        if type(self.blockers) is not tuple or any(
            type(blocker) is not PaperDeploymentBlocker for blocker in self.blockers
        ):
            raise PaperDeploymentError(
                "paper readiness blockers must be an exact tuple of blocker enums"
            )
        if len(set(self.blockers)) != len(self.blockers):
            raise PaperDeploymentConflict("paper readiness blockers must be unique")
        if self.blockers != tuple(sorted(self.blockers, key=_BLOCKER_ORDER.__getitem__)):
            raise PaperDeploymentConflict("paper readiness blockers are not in canonical order")
        if type(self._seal) is not _PaperDeploymentReadinessSeal:
            raise PaperDeploymentError("paper readiness report requires assessor construction")
        expected = _sha256(
            canonical_json_text(
                _readiness_material(
                    decision_sha256=self.decision_sha256,
                    evidence_sha256=self.evidence_sha256,
                    blockers=self.blockers,
                )
            )
        )
        if self._seal.payload_sha256 != expected:
            raise PaperDeploymentConflict("paper readiness report seal is invalid")

    @property
    def ready(self) -> bool:
        return not self.blockers

    @property
    def smoke_blockers(self) -> tuple[PaperDeploymentBlocker, ...]:
        return tuple(
            blocker for blocker in self.blockers if blocker in PAPER_SMOKE_DEPLOYMENT_BLOCKERS
        )

    @property
    def activation_blockers(self) -> tuple[PaperDeploymentBlocker, ...]:
        return tuple(
            blocker for blocker in self.blockers if blocker not in PAPER_SMOKE_DEPLOYMENT_BLOCKERS
        )

    @property
    def smoke_deployable(self) -> bool:
        """Whether packaging may proceed to a no-exposure deployed preflight."""

        return not self.smoke_blockers

    @property
    def phase5_activation_ready(self) -> bool:
        """Whether every distinct deployed Phase-5 authority has evidence."""

        return not self.blockers

    @property
    def report_id(self) -> str:
        return canonical_id(
            "paper-deployment-readiness-report",
            self.decision_sha256,
            self.evidence_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            _readiness_material(
                decision_sha256=self.decision_sha256,
                evidence_sha256=self.evidence_sha256,
                blockers=self.blockers,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return self._seal.payload_sha256

    @property
    def broker_action_authorized(self) -> bool:
        return False

    @property
    def new_exposure_authorized(self) -> bool:
        return False

    @property
    def live_trading_authorized(self) -> bool:
        return False

    @property
    def public_inbound_authorized(self) -> bool:
        return False

    @property
    def automatic_rearm_authorized(self) -> bool:
        return False


def assess_paper_deployment_readiness(
    *,
    decision: RecommendedPaperDeployment,
    evidence: PaperDeploymentEvidence,
) -> PaperDeploymentReadinessReport:
    """Assess the fixed profile from immutable, nonsecret evidence only."""

    if type(decision) is not RecommendedPaperDeployment:
        raise PaperDeploymentError(
            "paper readiness assessment requires an exact deployment decision"
        )
    decision.__post_init__()
    if type(evidence) is not PaperDeploymentEvidence:
        raise PaperDeploymentError("paper readiness assessment requires exact evidence")
    evidence.__post_init__()

    blockers: list[PaperDeploymentBlocker] = []
    if decision.environment is not PaperDeploymentEnvironment.PAPER:
        blockers.append(PaperDeploymentBlocker.ENVIRONMENT_NOT_PAPER)
    if decision.broker_mode is not PaperBrokerMode.ALPACA_PAPER:
        blockers.append(PaperDeploymentBlocker.LIVE_BROKER_SELECTED)
    if decision.network_mode is not PaperDeploymentNetworkMode.PRIVATE_OUTBOUND_ONLY:
        blockers.append(PaperDeploymentBlocker.PUBLIC_INBOUND_ENABLED)
    if decision.database_provider is not PaperDatabaseProvider.SUPABASE_MANAGED_POSTGRESQL:
        blockers.append(PaperDeploymentBlocker.DATABASE_PROVIDER_NOT_RECOMMENDED)
    if decision.database_plan is not PaperDatabasePlan.SUPABASE_FREE:
        blockers.append(PaperDeploymentBlocker.DATABASE_PLAN_NOT_SUPABASE_FREE)
    if decision.worker_provider is not PaperWorkerProvider.LOCAL_OWNER_SUPERVISED:
        blockers.append(PaperDeploymentBlocker.WORKER_PROVIDER_NOT_LOCAL_OWNER_SUPERVISED)
    if decision.telemetry_provider is not PaperTelemetryProvider.SENTRY:
        blockers.append(PaperDeploymentBlocker.TELEMETRY_PROVIDER_NOT_RECOMMENDED)
    if (
        decision.primary_alert_provider is not PaperAlertProvider.DEFERRED
        or decision.fallback_alert_provider is not PaperAlertProvider.DEFERRED
    ):
        blockers.append(PaperDeploymentBlocker.ALERT_PROVIDER_NOT_DEFERRED)
    if not decision.strategy.matches_recommendation:
        blockers.append(PaperDeploymentBlocker.STRATEGY_PIN_MISMATCH)
    if decision.worker_provider is PaperWorkerProvider.LOCAL_OWNER_SUPERVISED:
        blockers.append(PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY)
    if (
        decision.primary_alert_provider is PaperAlertProvider.DEFERRED
        and decision.fallback_alert_provider is PaperAlertProvider.DEFERRED
    ):
        blockers.append(PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED)

    sources = evidence.sources
    missing_secret_blockers = (
        (
            sources.database_credentials,
            PaperDeploymentBlocker.DATABASE_SECRET_SOURCE_MISSING,
        ),
        (
            sources.broker_credentials,
            PaperDeploymentBlocker.BROKER_SECRET_SOURCE_MISSING,
        ),
        (
            sources.telemetry_credentials,
            PaperDeploymentBlocker.TELEMETRY_SECRET_SOURCE_MISSING,
        ),
        (
            sources.primary_alert_credentials,
            PaperDeploymentBlocker.PRIMARY_ALERT_SECRET_SOURCE_MISSING,
        ),
        (
            sources.fallback_alert_credentials,
            PaperDeploymentBlocker.FALLBACK_ALERT_SECRET_SOURCE_MISSING,
        ),
    )
    missing_source_blockers = (
        (sources.deployment_spec, PaperDeploymentBlocker.DEPLOYMENT_SPEC_SOURCE_MISSING),
        (sources.runtime_image, PaperDeploymentBlocker.RUNTIME_IMAGE_SOURCE_MISSING),
        (sources.alert_route_plan, PaperDeploymentBlocker.ALERT_ROUTE_SOURCE_MISSING),
        (
            sources.strategy_artifact,
            PaperDeploymentBlocker.STRATEGY_ARTIFACT_SOURCE_MISSING,
        ),
        (
            sources.strategy_manifest,
            PaperDeploymentBlocker.STRATEGY_MANIFEST_SOURCE_MISSING,
        ),
        (sources.risk_policy, PaperDeploymentBlocker.RISK_POLICY_SOURCE_MISSING),
        (
            sources.fill_correction_policy,
            PaperDeploymentBlocker.FILL_CORRECTION_SOURCE_MISSING,
        ),
        (
            sources.reconciliation_policy,
            PaperDeploymentBlocker.RECONCILIATION_SOURCE_MISSING,
        ),
        (
            sources.trusted_time_policy,
            PaperDeploymentBlocker.TRUSTED_TIME_SOURCE_MISSING,
        ),
        (
            sources.manual_rearm_policy,
            PaperDeploymentBlocker.MANUAL_REARM_SOURCE_MISSING,
        ),
        (
            sources.control_alert_policy,
            PaperDeploymentBlocker.CONTROL_ALERT_POLICY_SOURCE_MISSING,
        ),
        (
            sources.heartbeat_watchdog_spec,
            PaperDeploymentBlocker.HEARTBEAT_WATCHDOG_SOURCE_MISSING,
        ),
        (
            sources.deployed_drill_plan,
            PaperDeploymentBlocker.DEPLOYED_DRILL_PLAN_SOURCE_MISSING,
        ),
    )
    blockers.extend(blocker for source, blocker in missing_secret_blockers if source is None)
    blockers.extend(blocker for source, blocker in missing_source_blockers if source is None)
    if (
        sources.strategy_artifact is not None
        and sources.strategy_artifact.content_sha256 != NO_EXPOSURE_SMOKE_ARTIFACT_SHA256
    ):
        blockers.append(PaperDeploymentBlocker.STRATEGY_ARTIFACT_SOURCE_MISMATCH)
    if (
        sources.strategy_manifest is not None
        and sources.strategy_manifest.content_sha256 != NO_EXPOSURE_SMOKE_MANIFEST_SHA256
    ):
        blockers.append(PaperDeploymentBlocker.STRATEGY_MANIFEST_SOURCE_MISMATCH)

    independence = evidence.provider_independence
    if independence is None:
        blockers.append(PaperDeploymentBlocker.PROVIDER_INDEPENDENCE_EVIDENCE_MISSING)
    else:
        if not _independence_binding_matches(independence, sources):
            blockers.append(PaperDeploymentBlocker.PROVIDER_INDEPENDENCE_BINDING_MISMATCH)
        if not independence.operationally_verified:
            blockers.append(PaperDeploymentBlocker.PROVIDER_INDEPENDENCE_UNVERIFIED)

    risk = evidence.authoritative_risk
    if risk is None:
        blockers.append(PaperDeploymentBlocker.AUTHORITATIVE_RISK_EVIDENCE_MISSING)
    else:
        if not _source_binding_matches(risk.risk_policy_sha256, sources.risk_policy):
            blockers.append(PaperDeploymentBlocker.AUTHORITATIVE_RISK_BINDING_MISMATCH)
        if not risk.operationally_verified:
            blockers.append(PaperDeploymentBlocker.AUTHORITATIVE_RISK_UNVERIFIED)

    fills = evidence.correction_safe_fills
    if fills is None:
        blockers.append(PaperDeploymentBlocker.CORRECTION_SAFE_FILL_EVIDENCE_MISSING)
    else:
        if not _source_binding_matches(
            fills.fill_correction_policy_sha256,
            sources.fill_correction_policy,
        ):
            blockers.append(PaperDeploymentBlocker.CORRECTION_SAFE_FILL_BINDING_MISMATCH)
        if not fills.operationally_verified:
            blockers.append(PaperDeploymentBlocker.CORRECTION_SAFE_FILL_UNVERIFIED)

    reconciliation = evidence.qualified_reconciliation
    if reconciliation is None:
        blockers.append(PaperDeploymentBlocker.QUALIFIED_RECONCILIATION_EVIDENCE_MISSING)
    else:
        if not _source_binding_matches(
            reconciliation.reconciliation_policy_sha256,
            sources.reconciliation_policy,
        ):
            blockers.append(PaperDeploymentBlocker.QUALIFIED_RECONCILIATION_BINDING_MISMATCH)
        if not reconciliation.operationally_verified:
            blockers.append(PaperDeploymentBlocker.QUALIFIED_RECONCILIATION_UNVERIFIED)

    time_rearm = evidence.trusted_time_manual_rearm
    if time_rearm is None:
        blockers.append(PaperDeploymentBlocker.TRUSTED_TIME_REARM_EVIDENCE_MISSING)
    else:
        if not _trusted_time_rearm_binding_matches(time_rearm, sources):
            blockers.append(PaperDeploymentBlocker.TRUSTED_TIME_REARM_BINDING_MISMATCH)
        if not time_rearm.operationally_verified:
            blockers.append(PaperDeploymentBlocker.TRUSTED_TIME_REARM_UNVERIFIED)

    fixed_paused = evidence.fixed_paused_control_alert
    if fixed_paused is None:
        blockers.append(PaperDeploymentBlocker.FIXED_PAUSED_CONTROL_ALERT_EVIDENCE_MISSING)
    else:
        if not _fixed_paused_control_alert_binding_matches(fixed_paused, sources):
            blockers.append(PaperDeploymentBlocker.FIXED_PAUSED_CONTROL_ALERT_BINDING_MISMATCH)
        if not fixed_paused.operationally_verified:
            blockers.append(PaperDeploymentBlocker.FIXED_PAUSED_CONTROL_ALERT_UNVERIFIED)

    heartbeat = evidence.external_heartbeat_watchdog
    if heartbeat is None:
        blockers.append(PaperDeploymentBlocker.EXTERNAL_HEARTBEAT_EVIDENCE_MISSING)
    else:
        if not _source_binding_matches(
            heartbeat.heartbeat_watchdog_spec_sha256,
            sources.heartbeat_watchdog_spec,
        ):
            blockers.append(PaperDeploymentBlocker.EXTERNAL_HEARTBEAT_BINDING_MISMATCH)
        if not heartbeat.operationally_verified:
            blockers.append(PaperDeploymentBlocker.EXTERNAL_HEARTBEAT_UNVERIFIED)

    drill = evidence.deployed_drill
    if drill is None:
        blockers.append(PaperDeploymentBlocker.DEPLOYED_DRILL_EVIDENCE_MISSING)
    else:
        if not _drill_binding_matches(drill, decision, sources):
            blockers.append(PaperDeploymentBlocker.DEPLOYED_DRILL_BINDING_MISMATCH)
        if not drill.safety_checks_passed:
            blockers.append(PaperDeploymentBlocker.DEPLOYED_DRILL_FAILED)

    ordered_blockers = tuple(sorted(set(blockers), key=_BLOCKER_ORDER.__getitem__))
    material = _readiness_material(
        decision_sha256=decision.semantic_sha256,
        evidence_sha256=evidence.semantic_sha256,
        blockers=ordered_blockers,
    )
    return PaperDeploymentReadinessReport(
        decision_sha256=decision.semantic_sha256,
        evidence_sha256=evidence.semantic_sha256,
        blockers=ordered_blockers,
        _seal=_PaperDeploymentReadinessSeal(payload_sha256=_sha256(canonical_json_text(material))),
    )


__all__ = [
    "PAPER_DEPLOYMENT_BLOCKER_ORDER",
    "PAPER_DEPLOYMENT_CONTRACT_VERSION",
    "PAPER_SMOKE_DEPLOYMENT_BLOCKERS",
    "AlertProviderIndependenceEvidence",
    "AuthoritativeRiskEvidence",
    "AuthoritativeSourcePin",
    "CorrectionSafeFillEvidence",
    "DeployedPaperDrillEvidence",
    "ExternalHeartbeatWatchdogEvidence",
    "FixedPausedControlAlertEvidence",
    "OpaqueSecretReference",
    "PaperAlertProvider",
    "PaperBrokerMode",
    "PaperDatabasePlan",
    "PaperDatabaseProvider",
    "PaperDeploymentAuthoritativeSources",
    "PaperDeploymentBlocker",
    "PaperDeploymentConflict",
    "PaperDeploymentEnvironment",
    "PaperDeploymentError",
    "PaperDeploymentEvidence",
    "PaperDeploymentNetworkMode",
    "PaperDeploymentReadinessReport",
    "PaperSecretPurpose",
    "PaperSourceKind",
    "PaperTelemetryProvider",
    "PaperWorkerProvider",
    "PinnedNoExposureStrategy",
    "QualifiedReconciliationEvidence",
    "RecommendedPaperDeployment",
    "TrustedTimeManualRearmEvidence",
    "assess_paper_deployment_readiness",
]
