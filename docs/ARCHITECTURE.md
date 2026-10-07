# Agentic SRE Platform — Design Document v1.0

> Status: **DRAFT — awaiting approval**
> Scope: full architecture per spec §32 items 1–18. MVP boundary = Phase 1 (§28).
> Guiding rule (§30): simplest architecture that satisfies the requirement. No Kubernetes/Kafka/microservices infrastructure merely because it is interesting.

---

## 0. Executive summary

An application-centric reliability platform with three deployable pieces:

1. **Server Agent** — a small Python daemon installed on each monitored VM. Discovers applications (process → port → systemd/docker → nginx vhost → domain), collects metrics/logs, performs health checks, executes remediation. Talks to the core over HTTPS with a per-server token. Collect-only by default; execution is pulled, never pushed.
2. **Core Platform** — one FastAPI service (API + orchestrator + findings/incident engines) with PostgreSQL + SQLite fallback. Owns the normalized data model, timeline, findings, incidents, SLO math, and the LLM investigation loop.
3. **Web UI** — server-rendered FastAPI + HTMX (same pattern as the existing Sentiment/Knowledge Center stack) with a per-application dashboard, global overview, live timeline, Ask Agent chat.

The LLM is an **investigator**, not an operator: it receives pre-collected evidence packs, produces findings/diagnoses/postmortems with explicit confidence labels, and can only propose actions. Execution flows through an action-gateway with allowlists, autonomy levels, and an immutable audit log.

Phase 1 runs the whole loop on a single VM with zero external dependencies beyond an LLM endpoint: discover → observe → detect → investigate → timeline → postmortem.

---

## 1. Product architecture (§32.1)

### 1.1 Layers

```text
┌────────────────────────────────────────────────────────────┐
│ Web UI (FastAPI + HTMX, :9140)                             │
│ overview · app dashboard · timeline · findings · ask-agent │
├────────────────────────────────────────────────────────────┤
│ Core API (FastAPI, :9141)  — same process as UI in MVP     │
│ entities · findings · incidents · SLO · deployments        │
├────────────────────────────────────────────────────────────┤
│ Orchestrator                                               │
│ ├─ Ingest (agent heartbeats, metrics, logs, health)        │
│ ├─ Detection engine (rules → Findings → Incidents)         │
│ ├─ Investigation engine (LLM over evidence packs)          │
│ ├─ Action gateway (allowlist + approval + audit)           │
│ └─ Postmortem generator                                    │
├────────────────────────────────────────────────────────────┤
│ Knowledge layer                                            │
│ ├─ Postgres/SQLite (system of record)                      │
│ ├─ Git reader (clone/pull per-app repos, read-only MVP)    │
│ └─ LLM client (OpenAI-compatible, provider-agnostic)       │
├────────────────────────────────────────────────────────────┤
│ Server Agent (per VM, :9142 loop) — pulls work, pushes data│
│ ├─ Discovery (process/systemd/docker/nginx)                │
│ ├─ Collectors (proc, health HTTP, log tails, journald)     │
│ └─ Executor (allowlisted actions only)                     │
└────────────────────────────────────────────────────────────┘
```

### 1.2 Key decisions

| Decision | Why | Problem it solves | Alternatives | Why not |
|---|---|---|---|---|
| Pull-based agent (agent polls core for work + posts data) | One open port, no inbound firewall to monitored VMs, agent behind NAT works | Connectivity/credential sprawl | Core pushes to agents via SSH/queue | Needs inbound access to every VM; queue (Redis/RabbitMQ) is infra for no Phase-1 benefit |
| Agent is **collect + execute only**, all intelligence in core | Agent updatable rarely; detection logic versioned in one place; agent compromise = read-only exposure | Security blast radius (§27) | Smart agent with local LLM | Heavier agent, harder upgrades, duplicated detection logic |
| Normalized `Application → Workload → Runtime` model (spec §6) | One dashboard works for monolith, compose, k8s identically | Per-deployment-type code fork | Per-model schemas | Exponential UI/API complexity |
| Findings as first-class rows with evidence arrays | Timeline, postmortems, Ask-Agent all read the same store; LLM never sees raw metrics, only curated evidence | Token cost, hallucination, no provenance | LLM watches live streams | Unverifiable outputs, violates "never fabricate evidence" |
| SQLite default, Postgres optional | MVP = single VM; zero-ops install | Deployment friction | Postgres-only | Blocks the "install on one box" success criterion (§31) |
| HTMX + server-rendered HTML | Matches existing stack/skills on this VM, no SPA build chain | Time-to-MVP | React/Vite SPA | Build tooling, auth surface, 2× codebase for same screens |

### 1.3 Component diagram (deployment view)

```text
                 ┌────────────── Monitored VM A ──────────────┐
                 │  sre-agent (systemd)                       │
                 │  discovery / collectors / executor         │
                 └───────────────┬────────────────────────────┘
                                 │ HTTPS POST /ingest (token)
                                 │ HTTPS POST /actions/poll
   ┌─────────────────────────────┴──────────────────────────┐
   │ Core VM (this one)                                     │
   │  nginx :443  ── /sre/ ──►  sre-platform :9141           │
   │                            ├─ API + UI + orchestrator  │
   │                            ├─ Postgres (or SQLite)     │
   │                            └─ LLM client → 9router     │
   └────────────────────────────────────────────────────────┘
```

---

## 2. Technology stack (§32.2)

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.12 everywhere | One language for agent + core; psutil/systemd/docker SDKs mature |
| API/UI | FastAPI + Jinja2 + HTMX | Async ingest, same-render loop for dashboards, no node toolchain |
| DB | SQLAlchemy 2.0 → SQLite (default) / PostgreSQL (prod) | Portable; Alembic migrations from day 1 |
| Metrics store | Same DB, downsampled tables (30s raw 48h → 5m rollups 30d) | Small scale; no TSDB until >10 apps or >1 week sub-minute queries |
| Logs | File/journald tails shipped in ingest batches, stored ≤7d | Cheap correlation beats a log index for MVP |
| Agent runtime | stdlib + psutil + requests | Minimal install (`pip install sre-agent`) |
| LLM | OpenAI-compatible client, configurable base URL (9router `coding`) | Provider-agnostic per spec §26 |
| Git | PyGithub (Phase 2) + plain `git` CLI for read-only inspection | Read-only MVP needs no SDK |
| Auth | Session cookie (UI) + bearer token per server (agent) + RBAC roles | §27 minimum |
| Secrets | Fernet-encrypted columns; key from env/file 0600; never plaintext tokens (§27) | |

Explicitly deferred: Redis, Celery, Kafka, Docker-in-agent, Prometheus/Grafana, k8s client. Each has a clean adapter seam if/when needed (§26 requirement honored via interfaces, not via installing them).

---

## 3. MVP architecture (§32.3)

Phase 1 = single core + N agents, closed loop, no GitHub writes, no CD.

```text
Agent loop (30s): discover → collect → POST /ingest
Core ingest:      upsert app/workloads → store metrics → run health checks
Detection (every ingest + 60s sweep):
    rules (thresholds, trends, SSL expiry, dep-down, deploy-correlation)
    → Finding(severity, confidence, evidence[])
    → Incident if health=down or critical finding + timeline events
Investigation (on Incident): evidence pack → LLM → diagnosis w/ confidence
Timeline: append-only events from metrics/incidents/deploys/agent actions
Postmortem: on incident resolve → generator over full evidence → human-editable doc
UI: overview, app dashboard, timeline, findings, incidents, ask-agent
```

**Out of MVP:** PR generation, CI triggers, deploy execution, rollback, DORA, forecasting. Schema includes `deployment`, `repository`, `slo` tables now so Phase 2/3 adds code, not migrations of existing data.

---

## 4. Application data model (§32.5)

Normalized entity graph (spec §25):

```text
Server 1─* Application 1─* Workload 1─* Process|Container|Pod
Application *─* Dependency (self-relation + external)
Application 1─1 Repository (optional)
Application 1─* Endpoint ─* Domain
Application 1─* HealthCheck · MetricPoint · LogBatch
Application 1─* Finding 1─* Evidence
Application 1─* Incident 1─* IncidentEvent · Investigation
Application 1─* Deployment 1─* Commit
Application 1─* AgentAction · Remediation
Application 1─* SLO 1─1 ErrorBudgetState
Incident 1─1 Postmortem
```

Core tables (DDL-level detail in `docs/schema.md` at implementation time; columns summarized):

- **server**: id, hostname, agent_version, token_hash, last_seen, labels
- **application**: id, name, slug, environment, owner, tags[], deployment_model ∈ {process, docker, compose, k8s, external, unknown}, status ∈ {healthy, degraded, down, unknown}, discovery ∈ {auto, manual, hybrid}, server_id, description
- **workload**: id, app_id, kind ∈ {process, container, pod, service, worker}, name, runtime (e.g. java/node/python), source ∈ {systemd, docker, k8s, manual}, external_id (unit name / container id / pod uid)
- **runtime_instance**: id, workload_id, pid, container_id, host_port, listen_addr, cmd, cwd, user, started_at
- **endpoint**: id, app_id, kind ∈ {http, tcp}, url, domain, vhost, tls_expires_at, upstream (nginx location/proxy_pass)
- **dependency**: id, app_id, name, kind ∈ {db, cache, queue, api, service}, target_app_id nullable, conn_string_hash, criticality
- **health_check**: id, app_id, kind ∈ {http, tcp, process}, target, interval_s, last_result, last_ok_at, consecutive_failures
- **metric_point**: id, app_id, ts, req_rate, err_rate_2xx..5xx, p50/p95/p99_ms, cpu_pct, mem_pct, …
- **metric_rollup_5m**: same dims downsampled (retention 30d)
- **log_batch**: id, app_id, workload_id, ts_start, ts_end, level_counts{json}, sample_lines[≤20], source
- **finding**: id, app_id, workload_id, category ∈ {performance, reliability, security, operational, deployment, capacity}, severity ∈ {critical, warning, info}, confidence ∈ {confirmed, likely, hypothesis}, status ∈ {open, ack, resolved, suppressed}, title, observation, probable_cause, recommendation, evidence[json: {source, ts, value, ref}], first_seen, last_seen, updated_at
- **incident**: id, app_id, severity, status ∈ {open, investigating, identified, mitigated, resolved}, impact, root_cause, confidence, detected_at, resolved_at, mttr_s
- **incident_event**: id, incident_id, ts, kind, summary, ref (finding/evidence ids)
- **deployment**: id, app_id, repo_id, sha, branch, message, author, method, deployed_at, status, result ∈ {success, failed, rolled_back}, before/after metric snapshot
- **repository**: id, app_id, url, default_branch, provider, token_ref (encrypted), last_indexed_at
- **agent_action**: id, app_id, incident_id, actor ∈ {agent, user:<name>, system}, action, target, reason, evidence_ref, result, risk ∈ {low, medium, high, critical}, approval_id, created_at
- **remediation**: id, finding/incident ref, proposed actions[json], status ∈ {proposed, approved, executed, rejected, failed}
- **slo**: id, app_id, sli ∈ {availability, latency_p95}, target, window
- **error_budget_state**: slo_id, period_start, budget_total_s, budget_burned_s, exhausted bool
- **timeline_event**: id, app_id, ts, actor, kind ∈ {metric, health, finding, incident, deployment, commit, agent, remediation, note}, payload[json] — append-only, the spine of §12
- **postmortem**: id, incident_id, doc[json sections], generated_by, reviewed_by, created_at

**Anti-lock-in check (§26):** every infra touchpoint goes through an interface — `RuntimeAdapter` (systemd/docker/k8s), `Collector`, `ActionExecutor`, `GitProvider`, `LLMClient`, `DeploymentAdapter`. Agent ships systemd + native-process adapters in Phase 1; docker adapter Phase 2; k8s Phase 4.

---

## 5. Server-agent architecture (§32.6)

```text
sre-agent (python, single daemon, systemd unit)
├─ config.toml        core_url, token, collect_interval, caps
├─ discovery.py       every 5 min:
│    psutil.process_iter → group by cwd/port → candidate apps
│    systemd list-units (python3/systemd) → unit ↔ pid
│    docker API (if socket present, Phase 2)
│    nginx -T parse → server_name/location/proxy_pass → domain map
│    merge → AppFingerprint{name?, ports[], units[], vhosts[]}
├─ collectors/        every 30s:
│    proc.py   (CPU/mem/fd per pid-group)
│    http.py   (health URL: code, latency)
│    logs.py   (tail N lines: journald -u / file tail; level counts + samples)
├─ ingest.py          batch POST /ingest {agent_ver, ts, discovery, metrics, health, logs}
├─ executor.py        POST /actions/poll → approved actions only → run → POST result
│    allowlist enforced BOTH core-side and agent-side (defense in depth)
└─ capabilities       declared in config: {collect:true, exec:false|allowlist[]}
```

Rules:
- Agent never opens a port (except loopback diagnostics); all comms outbound HTTPS.
- Token per server, revocable, stored 0600; TLS terminated at nginx core-side.
- Discovery is *additive*: auto-discovered apps enter `status=unknown/discovery=auto` and need one human confirm (name/env) before alerting — prevents noise storms and fulfills §4.1 ↔ §5 convergence (both paths write the same `application` row).
- Agent has no DB access, no LLM access, no git credentials. Compromise = data read of one VM + execution of an empty (default) allowlist.

### Server–agent protocol (§32.10)

| Endpoint | Dir | Payload |
|---|---|---|
| `POST /api/agent/v1/register` | → | hostname, caps, fingerprints → returns server_id |
| `POST /api/agent/v1/ingest` | → | discovery deltas, metric_points, health_checks, log_batches, agent self-status |
| `POST /api/agent/v1/actions/poll` | → | approved, unexpired actions (empty unless autonomy allows) |
| `POST /api/agent/v1/actions/{id}/result` | → | exit code, stdout tail, duration |
| `GET  /api/agent/v1/config` | ← | effective interval, allowlist version |

All responses include `min_interval` so the core can rate-limit fleets. Ingest is idempotent per (server, ts, batch nonce).

---

## 6. Agent (orchestrator) architecture (§32.7)

The "agent" users talk to = server-side orchestrator + LLM. Pipeline per ask/investigation:

```text
1. CONTEXT BUILDER   app → entity summary, active findings, last deployments,
                     dependency graph, recent timeline, metric rollups
2. TOOL CALLS (server-side, deterministic, logged as AgentAction):
     query_metrics(app, window, metric)
     query_logs(app, window, level)
     check_health(app)
     get_deployments(app, last_n)
     git_inspect(app, {file, log, diff, grep})   # read-only, Phase 2
     list_dependencies(app) / check_dependency(app)
     similar_incidents(app, symptom)
3. LLM STEP           receives evidence pack + tool results ONLY
                      must emit {claims: [{statement, confidence: confirmed|likely|hypothesis, evidence_refs[]}]}
4. SYNTHESIS          findings / diagnosis / recommendation / postmortem draft
5. ACTION GATE        any proposed action → remediation row (+ approval if L≥1)
```

Hard rules enforced in code, not prompt: every LLM claim must cite evidence_refs that exist; statements without refs are downgraded to `hypothesis` and rendered gray in UI; the orchestrator refuses to write anything except `finding/incident/postmortem/remediation/timeline` rows from LLM output.

### Agent tools & permissions (§32.8)

| Tool | Read | Write | Risk | Min autonomy |
|---|---|---|---|---|
| query_metrics/logs/health/deps | ✅ | — | — | L0 |
| git_inspect (read) | ✅ | — | — | L0 |
| create finding/incident/timeline | — | ✅ | — | L0 (system) |
| generate postmortem draft | — | ✅ | — | L0 |
| git_inspect (write: branch/commit/push) | — | ✅ | medium | L1 approval |
| restart service/container | — | ✅ | medium | L2 (pre-approved playbook) or L3 if allowlisted |
| config change, scale, deploy | — | ✅ | high | L1/L2 approval always |
| db/firewall/credential ops | — | — | critical | denylist — human only (§17) |

### Permission model (§32.9)

- **Autonomy levels** (§18) stored per (app × action-class): L0 observe, L1 recommend, L2 assisted (approved playbooks), L3 auto-execute only allowlisted low-risk set (restart, retry, cache clear, diagnostics).
- **RBAC roles**: `viewer`, `responder` (approve/execute), `owner` (edit apps, tokens, policy), `admin`. Per-app ownership optional.
- **Action gateway**: every execution = `AgentAction` row (actor/timestamp/action/target/reason/evidence/result — §18) created *before* run, result patched after. Denylist checked first, then allowlist, then autonomy level, then approval. Two enforcement points (core + agent) with different allowlist copies.
- Environment separation: prod apps flagged; prod + risk≥high ⇒ approval required regardless of autonomy L3.

---

## 7. Monitoring architecture (§32.11)

- **RED** per app: req_rate, err_rate (4xx/5xx split), p50/p95/p99 — from app logs (access-log parsing where available), health-check probes, and nginx vhost logs as fallback.
- **USE** per server + per workload: cpu/mem/disk/net/io via psutil; db connections & queue depth Phase 2 via dependency probes.
- **Health**: HTTP probe → TCP probe → process-alive, in that order, `consecutive_failures` hysteresis (3 fails = down, 2 oks = recovered) to stop flapping.
- **Storage**: 30s points 48h → 5m rollups 30d → hourly 1y. Detection queries run on rollups for trend findings, raw for incident windows.
- **Prioritization (§9)**: dashboard shows 4 numbers (status, err rate, p95, saturation-top); everything else behind drill-down. Finding engine does trend/z-score over baseline (same hour, weekdays) not absolute thresholds alone — avoids "disk 80% forever" noise in favor of "trending to full in 6h".

---

## 8. Incident lifecycle (§32.12)

```text
detect (health=down | critical finding)
  → incident(open) + timeline events + notify
  → investigation started (agent activity log §23 streams each step)
  → collect evidence pack (13-point checklist §14, skip N/A, log skips)
  → correlate: deps, deploys ±30min, config changes, similar incidents
  → LLM diagnosis → status=identified, root_cause + confidence + refs
  → remediation proposal (respecting autonomy) → execute or wait approval
  → health recovered (hysteresis) → status=mitigated → resolved (human or policy)
  → auto postmortem draft → review → published
```

Correlation rule baked in: any deployment within ±30 min of incident start ⇒ mandatory `deployment` evidence item, drives §19 regression check (before/after window metric diff auto-computed per deploy).

## 9. Postmortem generation flow (§32.13)

On `resolved`: orchestrator builds the full evidence dossier (timeline, findings + refs, metric windows, deploy diffs, agent actions, dependency states, prior similar incidents) → LLM fills the §20 template with `{claim, evidence_ref}` pairs → doc stored as editable JSON → UI render + export md/pdf. Facts (times, durations, error rates) are computed, not generated. Draft marked `generated_by=agent, reviewed_by=null` until a human approves; unreviewed drafts never modify SLO/learning data.

## 10. GitHub integration design (§32.15 — Phase 2)

- Per-app `repository` row; fine-grained PAT **read-only** by default; write token only in approval context, per-install scoped, encrypted (Fernet), never returned by API.
- Reader clones bare repo to `/var/lib/sre-platform/repos/<app>.git`, `git log/diff/grep` locally — fast, offline, no API rate limits.
- Indexer: file tree, Dockerfile, compose, CI manifests, README → embeddings-lite (structured summaries) for Ask-Agent context.
- Write path (Phase 2+): issue → branch `sre/fix/<incident-id>` → commit signed by bot identity → push → PR body links incident + evidence → CI status watched → all as AgentAction rows at L1. Never direct push to default branch.

## 11. CI/CD architecture (§32.14 — Phase 3)

`DeploymentAdapter` interface: `detect(deploy_event)` (ingest from agent watching systemd unit changes / container restarts / git pull) + `execute(plan)` + `verify(plan)` (smoke = health checks + regression windows) + `rollback(plan)`. Phase 3 ships `SystemdDeployAdapter` (git pull + restart + verify + auto-rollback on regression). GitHub Actions webhook in, status out. DORA computed from `deployment` + `incident` tables — pure aggregation.

## 12. Security architecture (§32.16)

| Threat | Control |
|---|---|
| Agent token leak | per-server token, revocable, scoped to ingest+poll; IP allowlist optional |
| Agent compromised | agent holds no secrets beyond its token; default exec allowlist empty; actions require core-signed approval nonce (single-use, 5-min expiry) |
| LLM prompt injection via logs | evidence packs are JSON with source labels; LLM output constrained to schema; no tool-execution inside LLM loop — orchestrator mediates every tool call |
| Token/credential storage | Fernet-encrypted at rest, key file 0600, mask in all API responses |
| Public UI | nginx basic auth + session; HTTPS via existing cert; audit log append-only table |
| Prod blast radius | env flag + risk class + denylist + approval workflow (§27 full checklist mapped 1:1) |

## 13. Repository structure (§32.16)

```text
SRE-Agentic/
├─ README.md
├─ docs/
│  ├─ ARCHITECTURE.md        (this doc)
│  ├─ schema.md              (DDL + ERD, written at milestone M2)
│  ├─ api-contracts.md       (§32.8 contracts, M2)
│  └─ runbook-agent-install.md
├─ platform/                 # core (FastAPI)
│  ├─ app/main.py            # API + UI mount
│  ├─ app/models.py          # SQLAlchemy
│  ├─ app/schemas/  app/api/ (routers)  app/ui/ (templates+static)
│  ├─ core/detection/        # rules engine
│  ├─ core/investigation/    # context builder, llm client, synthesis
│  ├─ core/actions/          # gateway, allowlists, approval
│  ├─ core/adapters/         # runtime.py systemd.py docker.py k8s.py git.py deploy.py
│  └─ tests/
├─ agent/                    # server agent (separate install)
│  ├─ sre_agent/{config,discovery,collectors,ingest,executor}.py
│  └─ tests/
├─ deploy/                   # systemd units, nginx conf, alembic
└─ Makefile
```

## 14. Development roadmap (§32.17)

| Milestone | Delivers (working state) | Phase |
|---|---|---|
| **M1** | Repo scaffold, models + Alembic, config, docker-free dev run, health of platform itself | — |
| **M2** | Agent v0: discovery (process/systemd/nginx) + ingest; manual registration API+UI; app dashboard (identity/runtime/network/health) | P1 |
| **M3** | Metrics store + RED/USE + health probes with hysteresis; global overview dashboard | P1 |
| **M4** | Logs ingest + viewer; findings engine v1 (threshold + trend + SSL + dep-down + deploy-correlation rules) | P1 |
| **M5** | Incident detection + timeline + agent activity log + investigation loop (LLM over evidence packs) + Ask Agent (read-only) | P1 |
| **M6** | Postmortem generator + SLO/error budget + review flow — **Phase 1 complete = §31 success criterion** | P1 |
| **M7** | GitHub read integration, repo awareness, deployment correlation | P2 |
| **M8** | Git write path (branch/commit/PR), CI watch | P2 |
| **M9** | Deploy adapter + verify + rollback + DORA | P3 |
| **M10** | Autonomy L3 playbooks, predictive findings, capacity forecast | P4 |

### MVP milestone breakdown (M2→M6 detail)

- **M2 (agent + discovery):** fingerprint merge algorithm, app confirm flow, dashboard static sections live. Exit: install agent on a second VM, app appears and is confirmable.
- **M3 (observe):** ingest pipeline + rollups, probe scheduler, overview counts, app health sparkline. Exit: kill a process → status flips to down.
- **M4 (findings):** rule engine + dedup/suppression (same finding updates last_seen instead of new row), finding detail with evidence table. Exit: restart with high latency → performance finding with trend evidence.
- **M5 (investigate):** incident auto-create, activity log streaming, evidence pack builder, LLM diagnosis with confidence + refs, Ask Agent on app page. Exit: kill process → incident auto-investigated citing recent deploy/log line.
- **M6 (document):** postmortem draft + edit + export; SLO config + budget burn; error-budget context in recommendations. Exit: full §31 loop demo on a deliberately-broken demo app.

---

## 15. Open decisions for review

1. **Core placement** — same VM (69.5.22.24, 13G free) behind existing nginx at `/sre/`, port 9141? (Recommended: yes; SQLite start, Postgres if >10 apps.)
2. **LLM route** — reuse 9router `coding` endpoint, or dedicated cheaper model for the 30s-detection loop? (Recommendation: rules do detection; LLM only on incident + Ask — cost control without extra infra.)
3. **First target app** — point the MVP at a real app on this VM (dashboard, KC, sentiment app) as the demo workload?
4. **Repo hygiene** — init with the doc above as `docs/ARCHITECTURE.md` + README now, code lands per milestone?
5. **Product name/slug** — "SRE-Agentic" as-is, or a product name for UI/branding?
