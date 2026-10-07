"""Normalized data model (spec §25).

Abstraction spine: Server -> Application -> Workload -> RuntimeInstance.
Every infra touchpoint is a value of a `kind` enum, never a separate table,
so monolith / docker / k8s share one dashboard + one API.
"""
from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


# ---------------------------------------------------------------- enums
class AppStatus(str, enum.Enum):
    healthy = "healthy"
    degraded = "degraded"
    down = "down"
    unknown = "unknown"


class DeploymentModel(str, enum.Enum):
    process = "process"
    docker = "docker"
    compose = "compose"
    k8s = "k8s"
    external = "external"
    unknown = "unknown"


class DiscoverySource(str, enum.Enum):
    auto = "auto"
    manual = "manual"
    hybrid = "hybrid"


class WorkloadKind(str, enum.Enum):
    process = "process"
    service = "service"
    container = "container"
    pod = "pod"
    deployment = "deployment"
    worker = "worker"


class Severity(str, enum.Enum):
    critical = "critical"
    warning = "warning"
    info = "info"


class Confidence(str, enum.Enum):
    confirmed = "confirmed"
    likely = "likely"
    hypothesis = "hypothesis"


class FindingCategory(str, enum.Enum):
    performance = "performance"
    reliability = "reliability"
    security = "security"
    operational = "operational"
    deployment = "deployment"
    capacity = "capacity"


class FindingStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"
    suppressed = "suppressed"


class IncidentStatus(str, enum.Enum):
    open = "open"
    investigating = "investigating"
    identified = "identified"
    mitigated = "mitigated"
    resolved = "resolved"


class RiskLevel(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Actor(str, enum.Enum):
    agent = "agent"
    user = "user"
    system = "system"


# ---------------------------------------------------------------- fleet
class Server(Base, TimestampMixin):
    __tablename__ = "server"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True)
    agent_version: Mapped[str | None] = mapped_column(String(32))
    token_hash: Mapped[str | None] = mapped_column(String(128))
    labels: Mapped[dict] = mapped_column(JSON, default=dict)
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    applications: Mapped[list[Application]] = relationship(back_populates="server")


# ---------------------------------------------------------------- application
class Application(Base, TimestampMixin):
    __tablename__ = "application"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    slug: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    environment: Mapped[str] = mapped_column(String(32), default="prod")
    description: Mapped[str | None] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(String(255))
    tags: Mapped[list] = mapped_column(JSON, default=list)

    deployment_model: Mapped[DeploymentModel] = mapped_column(
        Enum(DeploymentModel), default=DeploymentModel.unknown
    )
    status: Mapped[AppStatus] = mapped_column(Enum(AppStatus), default=AppStatus.unknown)
    discovery: Mapped[DiscoverySource] = mapped_column(
        Enum(DiscoverySource), default=DiscoverySource.manual
    )
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_discovery_fingerprint: Mapped[dict | None] = mapped_column(JSON)

    server_id: Mapped[int | None] = mapped_column(ForeignKey("server.id"))

    server: Mapped[Server | None] = relationship(back_populates="applications")
    workloads: Mapped[list[Workload]] = relationship(
        back_populates="application", cascade="all, delete-orphan"
    )
    endpoints: Mapped[list[Endpoint]] = relationship(
        back_populates="application", cascade="all, delete-orphan"
    )
    dependencies: Mapped[list[Dependency]] = relationship(
        back_populates="application",
        cascade="all, delete-orphan",
        foreign_keys="Dependency.application_id",
    )
    health_checks: Mapped[list[HealthCheck]] = relationship(
        back_populates="application", cascade="all, delete-orphan"
    )


class Workload(Base, TimestampMixin):
    __tablename__ = "workload"
    __table_args__ = (UniqueConstraint("application_id", "external_id", name="uq_workload_ext"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(ForeignKey("application.id"), index=True)
    kind: Mapped[WorkloadKind] = mapped_column(Enum(WorkloadKind), default=WorkloadKind.process)
    name: Mapped[str] = mapped_column(String(255))
    runtime: Mapped[str | None] = mapped_column(String(64))  # java / node / python / go
    source: Mapped[str | None] = mapped_column(String(32))  # systemd / docker / k8s / manual
    external_id: Mapped[str | None] = mapped_column(String(255))

    application: Mapped[Application] = relationship(back_populates="workloads")
    instances: Mapped[list[RuntimeInstance]] = relationship(
        back_populates="workload", cascade="all, delete-orphan"
    )


class RuntimeInstance(Base):
    __tablename__ = "runtime_instance"

    id: Mapped[int] = mapped_column(primary_key=True)
    workload_id: Mapped[int] = mapped_column(ForeignKey("workload.id"), index=True)
    pid: Mapped[int | None] = mapped_column(Integer)
    container_id: Mapped[str | None] = mapped_column(String(128))
    cwd: Mapped[str | None] = mapped_column(String(512))
    cmd: Mapped[str | None] = mapped_column(Text)
    user: Mapped[str | None] = mapped_column(String(64))
    listen_port: Mapped[int | None] = mapped_column(Integer)
    listen_addr: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alive: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    workload: Mapped[Workload] = relationship(back_populates="instances")


class Endpoint(Base, TimestampMixin):
    __tablename__ = "endpoint"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(ForeignKey("application.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="http")
    url: Mapped[str] = mapped_column(String(1024))
    domain: Mapped[str | None] = mapped_column(String(255))
    vhost: Mapped[str | None] = mapped_column(String(255))
    upstream: Mapped[str | None] = mapped_column(String(255))
    tls_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    application: Mapped[Application] = relationship(back_populates="endpoints")


class Dependency(Base, TimestampMixin):
    __tablename__ = "dependency"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(ForeignKey("application.id"), index=True)
    target_application_id: Mapped[int | None] = mapped_column(ForeignKey("application.id"))
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(32))  # db / cache / queue / api / service
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    application: Mapped[Application] = relationship(
        back_populates="dependencies", foreign_keys=[application_id]
    )


class HealthCheck(Base, TimestampMixin):
    __tablename__ = "health_check"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(ForeignKey("application.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="http")  # http / tcp / process
    target: Mapped[str] = mapped_column(String(1024))
    interval_s: Mapped[int] = mapped_column(Integer, default=30)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_result: Mapped[str | None] = mapped_column(String(16))  # ok / fail
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_latency_ms: Mapped[float | None] = mapped_column(Float)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    consecutive_oks: Mapped[int] = mapped_column(Integer, default=0)

    application: Mapped[Application] = relationship(back_populates="health_checks")


# ---------------------------------------------------------------- observability
class MetricPoint(Base):
    __tablename__ = "metric_point"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("application.id"), index=True)
    server_id: Mapped[int | None] = mapped_column(ForeignKey("server.id"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    req_rate: Mapped[float | None] = mapped_column(Float)
    err_rate: Mapped[float | None] = mapped_column(Float)
    http_2xx: Mapped[int | None] = mapped_column(Integer)
    http_3xx: Mapped[int | None] = mapped_column(Integer)
    http_4xx: Mapped[int | None] = mapped_column(Integer)
    http_5xx: Mapped[int | None] = mapped_column(Integer)
    p50_ms: Mapped[float | None] = mapped_column(Float)
    p95_ms: Mapped[float | None] = mapped_column(Float)
    p99_ms: Mapped[float | None] = mapped_column(Float)

    cpu_pct: Mapped[float | None] = mapped_column(Float)
    mem_pct: Mapped[float | None] = mapped_column(Float)
    disk_pct: Mapped[float | None] = mapped_column(Float)
    net_rx_kb: Mapped[float | None] = mapped_column(Float)
    net_tx_kb: Mapped[float | None] = mapped_column(Float)
    io_wait: Mapped[float | None] = mapped_column(Float)
    fd_count: Mapped[int | None] = mapped_column(Integer)
    procs: Mapped[int | None] = mapped_column(Integer)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)


class MetricRollup5m(Base):
    __tablename__ = "metric_rollup_5m"
    __table_args__ = (
        UniqueConstraint("application_id", "bucket", name="uq_rollup_app_bucket"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("application.id"), index=True)
    bucket: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    samples: Mapped[int] = mapped_column(Integer, default=0)
    err_rate_avg: Mapped[float | None] = mapped_column(Float)
    p95_avg: Mapped[float | None] = mapped_column(Float)
    p95_max: Mapped[float | None] = mapped_column(Float)
    cpu_avg: Mapped[float | None] = mapped_column(Float)
    mem_avg: Mapped[float | None] = mapped_column(Float)


class LogBatch(Base):
    __tablename__ = "log_batch"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("application.id"), index=True)
    workload_id: Mapped[int | None] = mapped_column(ForeignKey("workload.id"))
    ts_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ts_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str | None] = mapped_column(String(64))  # journald / file / docker
    level_counts: Mapped[dict] = mapped_column(JSON, default=dict)
    sample_lines: Mapped[list] = mapped_column(JSON, default=list)


# ---------------------------------------------------------------- reliability
class Finding(Base, TimestampMixin):
    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("application.id"), index=True)
    workload_id: Mapped[int | None] = mapped_column(ForeignKey("workload.id"))
    deployment_id: Mapped[int | None] = mapped_column(ForeignKey("deployment.id"))

    category: Mapped[FindingCategory] = mapped_column(Enum(FindingCategory))
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.info)
    confidence: Mapped[Confidence] = mapped_column(Enum(Confidence), default=Confidence.likely)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.open)

    rule_key: Mapped[str | None] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(512))
    observation: Mapped[str] = mapped_column(Text)
    probable_cause: Mapped[str | None] = mapped_column(Text)
    recommendation: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    """[{source, ts, value, ref}] — every claim must point here (spec §11)."""

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Incident(Base, TimestampMixin):
    __tablename__ = "incident"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("application.id"), index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.critical)
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), default=IncidentStatus.open)
    impact: Mapped[str | None] = mapped_column(Text)
    probable_root_cause: Mapped[str | None] = mapped_column(Text)
    root_cause: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[Confidence | None] = mapped_column(Enum(Confidence))
    investigation: Mapped[dict] = mapped_column(JSON, default=dict)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    identified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    mitigated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    mttr_s: Mapped[int | None] = mapped_column(Integer)


class IncidentEvent(Base):
    __tablename__ = "incident_event"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incident.id"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(32))
    summary: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)


class Repository(Base, TimestampMixin):
    __tablename__ = "repository"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(ForeignKey("application.id"), index=True)
    provider: Mapped[str] = mapped_column(String(32), default="github")
    url: Mapped[str] = mapped_column(String(1024))
    default_branch: Mapped[str] = mapped_column(String(128), default="main")
    token_ref: Mapped[str | None] = mapped_column(String(512))  # Fernet ciphertext
    last_indexed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Deployment(Base, TimestampMixin):
    __tablename__ = "deployment"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(ForeignKey("application.id"), index=True)
    repository_id: Mapped[int | None] = mapped_column(ForeignKey("repository.id"))
    sha: Mapped[str | None] = mapped_column(String(64), index=True)
    branch: Mapped[str | None] = mapped_column(String(128))
    message: Mapped[str | None] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(String(255))
    method: Mapped[str | None] = mapped_column(String(32))  # git-pull / systemd / docker / ci
    status: Mapped[str] = mapped_column(String(32), default="success")
    deployed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    before_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    after_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    regression: Mapped[bool] = mapped_column(Boolean, default=False)
    regression_checked: Mapped[bool] = mapped_column(Boolean, default=False)
    rollback_of_id: Mapped[int | None] = mapped_column(ForeignKey("deployment.id"))
    pr_url: Mapped[str | None] = mapped_column(String(512))
    ci_state: Mapped[str | None] = mapped_column(String(32))  # pending/success/failure/unknown
    ci_url: Mapped[str | None] = mapped_column(String(512))


class Commit(Base, TimestampMixin):
    __tablename__ = "commit"

    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repository.id"), index=True)
    sha: Mapped[str] = mapped_column(String(64), index=True)
    author: Mapped[str | None] = mapped_column(String(255))
    message: Mapped[str | None] = mapped_column(Text)
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AgentAction(Base):
    """Audit record (spec §18). Written BEFORE execution, result patched after."""

    __tablename__ = "agent_action"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("application.id"), index=True)
    server_id: Mapped[int | None] = mapped_column(ForeignKey("server.id"))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incident.id"))
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("finding.id"))

    actor: Mapped[Actor] = mapped_column(Enum(Actor), default=Actor.agent)
    actor_name: Mapped[str | None] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))  # restart_service / query_metrics / ...
    target: Mapped[str | None] = mapped_column(String(512))
    reason: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    risk: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel), default=RiskLevel.low)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    approval: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Remediation(Base, TimestampMixin):
    __tablename__ = "remediation"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("application.id"), index=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incident.id"))
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("finding.id"))
    title: Mapped[str] = mapped_column(String(512))
    rationale: Mapped[str | None] = mapped_column(Text)
    actions: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="proposed")
    risk: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel), default=RiskLevel.medium)
    evidence: Mapped[list] = mapped_column(JSON, default=list)


class SLO(Base, TimestampMixin):
    __tablename__ = "slo"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(ForeignKey("application.id"), index=True)
    sli: Mapped[str] = mapped_column(String(32))  # availability / latency_p95
    target: Mapped[float] = mapped_column(Float)  # 0.999
    target_ms: Mapped[float | None] = mapped_column(Float)  # for latency_p95
    window_days: Mapped[int] = mapped_column(Integer, default=30)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class ErrorBudgetState(Base, TimestampMixin):
    __tablename__ = "error_budget_state"

    id: Mapped[int] = mapped_column(primary_key=True)
    slo_id: Mapped[int] = mapped_column(ForeignKey("slo.id"), index=True)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    total_s: Mapped[float] = mapped_column(Float, default=0.0)
    burned_s: Mapped[float] = mapped_column(Float, default=0.0)
    current_pct: Mapped[float | None] = mapped_column(Float)
    exhausted: Mapped[bool] = mapped_column(Boolean, default=False)


class TimelineEvent(Base):
    """Append-only spine of the reliability timeline (spec §12)."""

    __tablename__ = "timeline_event"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("application.id"), index=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incident.id"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str | None] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)


class Postmortem(Base, TimestampMixin):
    __tablename__ = "postmortem"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incident.id"), unique=True)
    doc: Mapped[dict] = mapped_column(JSON, default=dict)
    generated_by: Mapped[str | None] = mapped_column(String(64))
    reviewed_by: Mapped[str | None] = mapped_column(String(128))
    published: Mapped[bool] = mapped_column(Boolean, default=False)


class User(Base, TimestampMixin):
    __tablename__ = "user"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="viewer")  # viewer/responder/owner/admin
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Setting(Base, TimestampMixin):
    """Runtime-editable settings + LLM analysis state."""

    __tablename__ = "setting"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(128), unique=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
