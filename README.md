# SRE-Agentic — Agentic Application Reliability Platform

AI-native SRE platform: discover → observe → detect → investigate → remediate → verify → postmortem, application-centric across monolith / docker / k8s.

**Status:** design phase — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Layout (planned)

```
platform/   core API + UI + orchestrator (FastAPI)
agent/      server agent (discovery, collectors, executor)
docs/       architecture, schema, API contracts
deploy/     systemd units, nginx
```

## Roadmap

M1 scaffold → M2 agent+discovery → M3 metrics+health → M4 findings → M5 incidents+investigation → M6 postmortems+SLO (= Phase 1 MVP). Then GitHub (P2), CI/CD+rollback (P3), autonomy (P4).
