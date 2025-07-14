# PIPELINE.md

*Last Updated: 2025-01-14*

## 1. Declarative Architecture Overview

| Component | Purpose | Key Configuration / Links |
|-----------|---------|---------------------------|
| **Benthos** | Ingest Wazuh webhooks, enrich with `trace_id`, `tenant`, geo/IP (optional). | `input.http_server → processors.bloblang → output.nats_stream` <br/> Publishes to **NATS JetStream** subject `alerts.ingest`. |
| **NATS JetStream** | Durable message bus, back-pressure, replay. | Streams:<br/>• `alerts.*` (raw / enriched)<br/>• `notify.*` (outbound)<br/>• `alerts.failed` (DLQ). |
| **Temporal** | SOAR brain; deterministic DAG for each alert. | Workers subscribe to `alerts.ingest`, launch `AlertWorkflow`.<br/>Activities: `GetAgentInfo`, `CallLLM`, `SaveToPostgres`, `SendNotification`.<br/>Retries & exponential back-off enabled. |
| **Postgres** | Persist enriched alerts, workflow state, tenant metadata. | Used by Temporal activities and for replay CLI. |
| **Vault** | Secrets for SMTP, LLM, NATS JWT, tenant keys. | Worker/Benthos pods side-load via Vault agent / templating. |
| **Prometheus** | Scrapes `/metrics` from Benthos, Temporal, NATS, node exporters. | Alerts via Alertmanager on queue depth, workflow failures. |
| **Loki** | Central log storage for Benthos & Temporal (stdout), NATS server logs. | Promtail/Vector agents add `tenant` & `trace_id` labels. |
| **Tempo** | Trace backend (OTLP port `4317`). | Collects spans from Benthos tracer + Temporal SDK.<br/>Linked to logs via shared `trace_id`. |
| **Grafana** | Unified dashboards: traces (Tempo), logs (Loki), metrics (Prometheus), geo-map panel. | “Pew-pew” geomap: source IP → tenant arc. |

> **Containerisation / Orchestration**  
> *Dev*: single `docker-compose.yml`.  
> *Prod*: Nomad jobs (separate groups for ingest, broker, workflows, observability).  
> All services publish OTEL traces, metrics, and structured logs.

---

## 2. Decision Journey (Imperative Narrative)

1. **Constraints Identified**  
   - Wazuh emits **only HTTP webhooks**.  
   - Goals: minimal moving parts, deterministic retries, multi-tenant support, strong CI/CD & observability.

2. **Early Options Explored**  
   - RabbitMQ vs NATS: RabbitMQ needed extra HTTP adapter; NATS JetStream gave durability + simpler ops.  
   - Direct HTTP → Temporal vs Benthos: Benthos offered zero-code webhook server, YAML transforms, hot reload.

3. **Key Trade-offs & Resolutions**  
   - **Decoupling**: Benthos ➜ NATS ➜ Temporal avoids tight coupling & adds replay.  
   - **ETL vs Workflow Logic**: Benthos keeps only light enrichment; Temporal owns business logic.  
   - **Retries/Backlog**: JetStream retained messages; Temporal activities add idempotent retries.

4. **“Aha” Moments**  
   - Realised Benthos can serve as *both* ingress & egress formatter while staying stateless.  
   - OpenTelemetry end-to-end tracing glues everything for quick RCA.  
   - Nomad + Vault provide clean secret & scheduling story without Kubernetes overhead.

---

## 3. Known Gotchas & Remaining Risks

| Risk / Gotcha | Severity | Mitigation Idea |
|---------------|----------|-----------------|
| JetStream disk exhaustion on burst replays | High | Alert on stream size; apply retention limits; tier to S3. |
| NATS outage cascades to entire pipeline | High | Deploy NATS cluster (3 nodes), enable leafnode for HA. |
| Per-tenant config drift / secret leakage | Medium | Isolate Vault namespaces & task queues, lint tenant configs in CI. |
| Schema drift in Wazuh alert JSON | Medium | Validate via CUE schema in Benthos; versioned converters. |
| GeoIP lookup latency during enrichment | Low | Cache lookups; move to async enrichment step. |
| Temporal workflow code changes vs running history | Low | Use workflow versioning API (`workflow.Version`). |

---

## 4. Validation & Drift-Control Measures

- **CI Tests**  
  - `benthos lint && benthos test ./tests/*.yaml` for every commit.  
  - Go unit + replay tests for each Temporal workflow (`workflowtest.NewTestWorkflowEnvironment`).  
  - NATS JetStream integration test ensures subjects/streams exist.

- **GitOps Pipelines** (Jenkins)  
  1. Lint / test.  
  2. Build container images, push with Git SHA tag.  
  3. `nomad job plan` + `nomad job run` via Terraform Cloud workspace.

- **Alerting**  
  - Prometheus → Alertmanager:  
    - `nats_stream_pending_messages > 1000` (warning).  
    - `temporal_failed_activities_total > 0` (critical).  
  - Loki log rules: 5× “panic” in 1 min triggers Slack.

- **Trace Sampling & SLOs**  
  - Tempo sampling 100 % of critical (`severity>=10`) alerts.  
  - Grafana alert if p95 end-to-end latency > 15 s.

- **Security & Secret Hygiene**  
  - Vault → short-lived NATS JWT tokens (TTL = 24 h).  
  - Automated secret rotation pipelines (Vault → Nomad template restart).

- **Replay / DR Drills**  
  - Quarterly script: pull 10 random alerts from JetStream and re-process to validate workflows.  
  - Postgres backup restore + JetStream snapshot restore tested in staging monthly.