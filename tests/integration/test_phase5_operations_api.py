from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from apps.api.backtest_views import (
    LOCAL_SESSION_COOKIE,
    LocalOperatorSecurity,
)
from apps.api.contracts import (
    ActiveCriticalAlertView,
    AdvancedRiskAssessmentView,
    AdvancedRiskAssignmentView,
    EnvironmentMode,
    OperationalControlTransitionView,
    OperationsCoordinatorStatus,
    OperationsCoordinatorView,
    OperationsEnvironmentView,
    OperationsOverviewResponse,
    OperationsReadinessView,
    ReadinessStatus,
)
from apps.api.operations_views import create_operations_router
from packages.application.operational_rearm import (
    AuthenticatedOperationalControlService,
    AuthoritativeOperationalRearmFacts,
)
from packages.domain.advanced_risk_assignment import (
    AdvancedRiskAssignmentCommand,
    AdvancedRiskPolicyAssignment,
    assign_advanced_risk_policy,
)
from packages.domain.advanced_risk_policy import AdvancedRiskDisposition
from packages.domain.critical_alert import CriticalAlertDeliveryState
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlConflict,
    OperationalControlIncidentDisposition,
    OperationalControlRearmRejected,
    OperationalControlState,
    OperationalControlTransition,
)
from packages.persistence.database import create_database_engine
from packages.persistence.operational_control import SqlOperationalControlRepository
from packages.persistence.schema import metadata, phase2_account_lease_heads

BASE = datetime(2026, 7, 28, 16, 0, tzinfo=UTC)
ACCOUNT = "phase5f-paper-account"


class FixedClock:
    def __init__(self, instant: datetime = BASE) -> None:
        self.instant = instant

    def __call__(self) -> datetime:
        return self.instant

    def now(self) -> datetime:
        return self.instant


def _initial_transition() -> OperationalControlTransition:
    from packages.domain.operational_control import apply_operational_control_command

    command = OperationalControlCommand(
        scope_id=ACCOUNT,
        idempotency_key="phase5f-initialize-0001",
        kind=OperationalControlCommandKind.INITIALIZE_HALTED,
        target_state=OperationalControlState.HALTED,
        actor=OperationalControlActor(
            actor_id="bootstrap",
            kind=OperationalControlActorKind.SYSTEM,
            authority_sha256="a" * 64,
            authenticated_at=None,
        ),
        reason_code="startup-fail-closed",
        reason_evidence_sha256="b" * 64,
        requested_at=BASE,
    )
    return apply_operational_control_command(None, command, decided_at=BASE)


class QueryStub:
    def __init__(self, transition: OperationalControlTransition) -> None:
        self.transition = transition
        self.calls: list[tuple[str, datetime]] = []

    def overview(
        self,
        account_id: str,
        *,
        as_of: datetime,
    ) -> OperationsOverviewResponse:
        self.calls.append((account_id, as_of))
        control = OperationalControlTransitionView(
            transition_id=self.transition.transition_id,
            sequence_number=self.transition.sequence_number,
            prior_state=self.transition.prior_state,
            effective_state=self.transition.effective_state,
            state_changed=self.transition.state_changed,
            state_epoch_id=self.transition.state_epoch_id,
            blocker_count=len(self.transition.blocking_events),
            blocker_overflowed=self.transition.blocker_overflowed,
            active_operation=None,
            decided_at=self.transition.decided_at,
        )
        return OperationsOverviewResponse(
            as_of=as_of,
            environment=OperationsEnvironmentView(
                name="paper-local",
                mode=EnvironmentMode.PAPER,
                account_id=account_id,
                loopback_only=True,
            ),
            readiness=OperationsReadinessView(
                status=ReadinessStatus.READY,
                reasons=[],
                as_of=as_of,
            ),
            coordinator=OperationsCoordinatorView(
                status=OperationsCoordinatorStatus.ACTIVE,
                owner_id="trader-process-1",
                fencing_generation=7,
                lease_expires_at=as_of + timedelta(seconds=20),
            ),
            control=control,
            control_history=[control],
            current_risk_assignment=AdvancedRiskAssignmentView(
                assignment_id="11111111-1111-1111-1111-111111111111",
                sequence_number=1,
                policy_id="moderate-paper-policy",
                policy_sha256="c" * 64,
                environment="paper",
                assigned_at=as_of,
            ),
            current_risk_assessment=AdvancedRiskAssessmentView(
                assessment_id="assessment-1",
                disposition=AdvancedRiskDisposition.PAUSE,
                assessed_at=as_of,
                valid_through=as_of + timedelta(seconds=5),
            ),
            active_alerts=[
                ActiveCriticalAlertView(
                    incident_id="incident-1",
                    alert_code="broker-disconnected",
                    recorded_at=as_of,
                    primary_delivery_state=CriticalAlertDeliveryState.CONFIRMED,
                    escalation_delivery_state=CriticalAlertDeliveryState.UNKNOWN,
                    primary_deadline_at=as_of + timedelta(seconds=15),
                    escalation_deadline_at=as_of + timedelta(seconds=30),
                )
            ],
        )


class ControlStub:
    def __init__(self, transition: OperationalControlTransition) -> None:
        self.transition = transition
        self.calls: list[tuple[str, str, str, object, str]] = []
        self.receipts: dict[str, tuple[object, str]] = {}
        self.reject_rearm = False

    def execute(
        self,
        *,
        account_id: str,
        operator_id: str,
        idempotency_key: str,
        kind: object,
        reason_code: str,
    ) -> OperationalControlTransition:
        self.calls.append((account_id, operator_id, idempotency_key, kind, reason_code))
        if self.reject_rearm and kind is OperationalControlCommandKind.REARM:
            raise OperationalControlRearmRejected(
                "raw-secret-provider-payload must never reach the browser"
            )
        prior = self.receipts.get(idempotency_key)
        if prior is not None and prior != (kind, reason_code):
            raise OperationalControlConflict("private conflict detail")
        self.receipts[idempotency_key] = kind, reason_code
        return self.transition


class AssignmentStub:
    approved_policy_id = "moderate-paper-policy"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.assignment = _assignment()

    def assign(
        self,
        *,
        account_id: str,
        operator_id: str,
        idempotency_key: str,
    ) -> AdvancedRiskPolicyAssignment:
        self.calls.append((account_id, operator_id, idempotency_key))
        return self.assignment


def _assignment() -> AdvancedRiskPolicyAssignment:
    command = AdvancedRiskAssignmentCommand(
        account_id=ACCOUNT,
        environment="paper",
        idempotency_key="phase5f-risk-assign-0001",
        policy_id="moderate-paper-policy",
        policy_sha256="c" * 64,
        actor_id="local-operator",
        actor_authority_sha256="d" * 64,
        actor_authenticated_at=BASE,
        requested_at=BASE,
        approval_evidence_sha256="e" * 64,
        expected_assignment_sequence_number=0,
        expected_assignment_sha256=None,
    )
    return assign_advanced_risk_policy(None, command, assigned_at=BASE)


def _app(
    *,
    persistence_ready: bool = True,
    assignment: AssignmentStub | None = None,
) -> tuple[FastAPI, QueryStub, ControlStub, FixedClock]:
    clock = FixedClock()
    security = LocalOperatorSecurity(
        enabled=True,
        transport_is_loopback_scoped=True,
        operator_id="local-operator",
        configured_secret="test-only-secret",
    )
    transition = _initial_transition()
    query = QueryStub(transition)
    control = ControlStub(transition)
    app = FastAPI()

    @app.get("/api/v1/test/bootstrap")
    def bootstrap(request: Request, response: Response) -> dict[str, object]:
        capability = security.bootstrap_capability(
            response,
            persistence_ready=True,
            issued_at=clock(),
            session_cookie=request.cookies.get(LOCAL_SESSION_COOKIE),
        )
        return capability.model_dump(mode="json")

    app.include_router(
        create_operations_router(
            query=query,
            control=control,
            security=security,
            persistence_ready=lambda: persistence_ready,
            assignment=assignment,
            clock=clock,
        ),
        prefix="/api/v1",
    )
    return app, query, control, clock


def _authorized(
    app: FastAPI,
) -> tuple[TestClient, dict[str, str]]:
    client = TestClient(app)
    response = client.get("/api/v1/test/bootstrap")
    assert response.status_code == 200
    csrf = response.json()["csrf_token"]
    assert isinstance(csrf, str)
    return client, {"X-CSRF-Token": csrf}


def test_operations_reads_require_session_and_csrf_and_are_allowlisted() -> None:
    app, query, _, _ = _app()
    path = f"/api/v1/operations/accounts/{ACCOUNT}"
    missing_session = TestClient(app).get(
        path,
        headers={"X-CSRF-Token": "x" * 43},
    )
    assert missing_session.status_code == 401

    client, headers = _authorized(app)
    bad_csrf = client.get(path, headers={"X-CSRF-Token": "x" * 43})
    assert bad_csrf.status_code == 403
    response = client.get(path, headers=headers)

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    payload = response.json()
    assert payload["environment"] == {
        "name": "paper-local",
        "mode": "paper",
        "account_id": ACCOUNT,
        "loopback_only": True,
    }
    assert payload["coordinator"]["fencing_generation"] == 7
    assert payload["control"]["effective_state"] == "halted"
    assert payload["current_risk_assignment"]["policy_id"] == "moderate-paper-policy"
    assert payload["current_risk_assessment"]["disposition"] == "pause"
    assert payload["active_alerts"][0]["alert_code"] == "broker-disconnected"
    serialized = response.text.lower()
    for forbidden in (
        "canonical_payload",
        "evidence_sha256",
        "authority_sha256",
        "lease_id",
        "secret",
        "raw_payload",
    ):
        assert forbidden not in serialized
    assert query.calls == [(ACCOUNT, BASE)]


def test_control_mutations_enforce_csrf_idempotency_and_exact_retries() -> None:
    app, _, control, _ = _app()
    client, csrf_headers = _authorized(app)
    path = f"/api/v1/operations/accounts/{ACCOUNT}/control/pause"
    missing_key = client.post(
        path,
        json={"reason_code": "operator-requested"},
        headers=csrf_headers,
    )
    assert missing_key.status_code == 422

    headers = {
        **csrf_headers,
        "Idempotency-Key": "phase5f-pause-0001",
    }
    first = client.post(
        path,
        json={"reason_code": "operator-requested"},
        headers=headers,
    )
    retry = client.post(
        path,
        json={"reason_code": "operator-requested"},
        headers=headers,
    )
    conflict = client.post(
        path,
        json={"reason_code": "different-reason"},
        headers=headers,
    )

    assert first.status_code == 200
    assert retry.status_code == 200
    assert retry.json() == first.json()
    assert first.json()["action"] == "pause"
    assert conflict.status_code == 409
    assert conflict.json() == {"detail": "idempotency or operational-control head conflicts"}
    assert "private" not in conflict.text
    assert len(control.calls) == 3


def test_rearm_body_cannot_supply_evidence_flags_digests_or_raw_payloads() -> None:
    app, _, control, _ = _app()
    client, csrf_headers = _authorized(app)
    headers = {
        **csrf_headers,
        "Idempotency-Key": "phase5f-rearm-0001",
    }
    path = f"/api/v1/operations/accounts/{ACCOUNT}/control/rearm"

    for untrusted_field, value in (
        ("reconciliation_clean", True),
        ("readiness_sha256", "f" * 64),
        ("working_order_ids", []),
        ("operation_completion", {}),
        ("raw_payload", {"healthy": True}),
    ):
        response = client.post(
            path,
            json={
                "reason_code": "operator-reviewed",
                untrusted_field: value,
            },
            headers=headers,
        )
        assert response.status_code == 422

    assert control.calls == []


def test_domain_and_persistence_errors_are_sanitized_and_fail_closed() -> None:
    app, _, control, _ = _app(persistence_ready=False)
    client, csrf_headers = _authorized(app)
    headers = {
        **csrf_headers,
        "Idempotency-Key": "phase5f-unavailable-0001",
    }
    path = f"/api/v1/operations/accounts/{ACCOUNT}/control/rearm"
    unavailable = client.post(
        path,
        json={"reason_code": "operator-reviewed"},
        headers=headers,
    )
    assert unavailable.status_code == 503
    assert control.calls == []

    ready_app, _, ready_control, _ = _app()
    ready_control.reject_rearm = True
    ready_client, ready_csrf = _authorized(ready_app)
    rejected = ready_client.post(
        path,
        json={"reason_code": "operator-reviewed"},
        headers={
            **ready_csrf,
            "Idempotency-Key": "phase5f-rejected-0001",
        },
    )
    assert rejected.status_code == 409
    assert "raw-secret-provider-payload" not in rejected.text


def test_assignment_route_exists_only_with_an_injected_fence_aware_service() -> None:
    path = f"/api/v1/operations/accounts/{ACCOUNT}/advanced-risk-assignment"
    app, _, _, _ = _app()
    client, headers = _authorized(app)
    absent = client.post(
        path,
        headers={**headers, "Idempotency-Key": "phase5f-assign-0001"},
    )
    assert absent.status_code == 404

    assignment = AssignmentStub()
    enabled_app, _, _, _ = _app(assignment=assignment)
    enabled_client, enabled_headers = _authorized(enabled_app)
    response = enabled_client.post(
        path,
        headers={
            **enabled_headers,
            "Idempotency-Key": "phase5f-assign-0001",
        },
    )
    assert response.status_code == 200
    assert response.json()["assignment"]["policy_id"] == "moderate-paper-policy"
    assert assignment.calls == [(ACCOUNT, "local-operator", "phase5f-assign-0001")]


def test_operations_http_dependency_surface_has_no_direct_broker_port() -> None:
    assert set(inspect.signature(create_operations_router).parameters) == {
        "query",
        "control",
        "security",
        "persistence_ready",
        "assignment",
        "clock",
    }
    assert set(inspect.signature(AuthenticatedOperationalControlService).parameters) == {
        "repository",
        "actor_authority_sha256",
        "rearm_verifier",
        "clock",
    }


def _sqlite_repository(
    path: Path,
) -> tuple[SqlOperationalControlRepository, FixedClock]:
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_lease_heads).values(
                account_id=ACCOUNT,
                last_fencing_generation=0,
                current_fencing_generation=None,
                current_lease_sha256=None,
                updated_at=BASE,
            )
        )
    clock = FixedClock()
    return SqlOperationalControlRepository(engine=engine, clock=clock), clock


class SqlRearmVerifier:
    def verify(
        self,
        current: OperationalControlTransition,
        *,
        checked_at: datetime,
    ) -> AuthoritativeOperationalRearmFacts:
        dispositions = tuple(
            sorted(
                (
                    OperationalControlIncidentDisposition(
                        event_id=event.event_id,
                        event_sha256=event.semantic_sha256,
                        resolution_code="operator-reviewed",
                        resolution_evidence_sha256="e" * 64,
                        resolved_at=checked_at,
                    )
                    for event in current.blocking_events
                ),
                key=lambda item: item.event_id,
            )
        )
        return AuthoritativeOperationalRearmFacts(
            scope_id=current.scope_id,
            current_transition_id=current.transition_id,
            current_transition_sha256=current.semantic_sha256,
            current_state=current.effective_state,
            current_state_epoch_id=current.state_epoch_id,
            checked_at=checked_at,
            expires_at=checked_at + timedelta(seconds=30),
            readiness_sha256="f" * 64,
            reconciliation_sha256="1" * 64,
            incident_register_sha256="2" * 64,
            reconciliation_clean=True,
            data_healthy=True,
            clock_healthy=True,
            working_order_ids=(),
            unknown_order_ids=(),
            pending_cancel_order_ids=(),
            incident_dispositions=dispositions,
        )


def test_sql_repository_commits_only_explicit_authenticated_rearm_path(
    tmp_path: Path,
) -> None:
    repository, clock = _sqlite_repository(tmp_path / "operations.sqlite")
    initialize = OperationalControlCommand(
        scope_id=ACCOUNT,
        idempotency_key="phase5f-sql-initialize-0001",
        kind=OperationalControlCommandKind.INITIALIZE_HALTED,
        target_state=OperationalControlState.HALTED,
        actor=OperationalControlActor(
            actor_id="bootstrap",
            kind=OperationalControlActorKind.SYSTEM,
            authority_sha256="a" * 64,
            authenticated_at=None,
        ),
        reason_code="startup-fail-closed",
        reason_evidence_sha256="b" * 64,
        requested_at=BASE,
    )
    repository.apply(initialize)
    clock.instant += timedelta(seconds=1)
    service = AuthenticatedOperationalControlService(
        repository=repository,
        actor_authority_sha256="9" * 64,
        rearm_verifier=SqlRearmVerifier(),
        clock=clock,
    )
    rearmed = service.execute(
        account_id=ACCOUNT,
        operator_id="local-operator",
        idempotency_key="phase5f-sql-rearm-0001",
        kind=OperationalControlCommandKind.REARM,
        reason_code="operator-reviewed",
    )
    retry = service.execute(
        account_id=ACCOUNT,
        operator_id="local-operator",
        idempotency_key="phase5f-sql-rearm-0001",
        kind=OperationalControlCommandKind.REARM,
        reason_code="operator-reviewed",
    )
    assert retry == rearmed
    assert repository.load(ACCOUNT) == rearmed

    raw_rearm = OperationalControlCommand(
        scope_id=ACCOUNT,
        idempotency_key="phase5f-raw-rearm-0001",
        kind=OperationalControlCommandKind.REARM,
        target_state=OperationalControlState.RUNNING,
        actor=OperationalControlActor(
            actor_id="local-operator",
            kind=OperationalControlActorKind.HUMAN,
            authority_sha256="9" * 64,
            authenticated_at=clock(),
        ),
        reason_code="unverified-browser-claim",
        reason_evidence_sha256="4" * 64,
        requested_at=clock(),
        rearm_evidence_sha256="5" * 64,
    )
    with pytest.raises(OperationalControlRearmRejected, match="rejects REARM"):
        repository.apply(raw_rearm)
