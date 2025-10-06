# Velocity Documentation Hub

Velocity ships with an extensive documentation suite to help operators, developers, security teams, and partner integrators adopt the protocol confidently. This hub is your navigation surface—every guide, reference, and whitepaper is indexed here with target audiences and prerequisites.

## 1. Orientation

| Document | Audience | Why you should read it |
|----------|----------|------------------------|
| [User Handbook](./user-handbook.md) | Platform engineers, SREs, early adopters | End-to-end walkthrough covering installation, simplified configs, CLI usage, telemetry, troubleshooting, and FAQ. |
| [Deployment Guide](./deployment.md) | Infrastructure teams | Production playbooks: single-node pilots, HA clusters, load-balancer steering, certificate automation, disaster recovery. |
| [Developer Guide](./developer-guide.md) | Contributors, auditors | Workspace layout, build matrix, linting, test suites, fuzzing, coding conventions, API stability guarantees. |
| [Integration Guide](./integration-guide.md) | Full-stack engineers, product teams | Reverse proxy patterns, Service Mesh interop, embedding Velocity into existing HTTP pipelines, SaaS integration checklists. |
| [Upgrade Guide](./upgrade-guide.md) | Release managers | Semver policy, migration testing, blue/green deployment strategy, rollback procedures. |

## 2. Security & Cryptography

* [Security Design](./security-design.md) — Hybrid cryptography rationale, threat model analysis, certificate policy, PQ signature validation flows, incident response hooks.
* [Velocity Exploit Hardening](./velocity-exploit-hardening.md) — Memory-safety posture, sandboxing recommendations, hardening flags, kernel tuning, red-team scenarios.
* [Velocity SSH Migration](./velocity-ssh-migration.md) — SSH transport mapping, host key bridging, PAM integration, audit logging, staged rollout plan.
* [HTTPS Migration Guide](./https-migration.md) — Browser compatibility roadmap, Nginx/Envoy front-door configuration, fallback monitoring.
* [HTTPS Roadmap](./https-roadmap.md) — Quarter-by-quarter initiatives to converge browsers on Velocity, CA ecosystem milestones, compatibility gates.

## 3. Operations & Performance

* [Benchmarking Playbook](./benchmarking.md) — Reproducing handshake microbenchmarks, page-load trials, AF_XDP fast-path tests, CSV interpretation, Grafana dashboards.
* [Performance & Security Roadmap](./performance-security-roadmap.md) — Targets for latency, throughput, CPU budgets, privacy enhancements, kernel bypass adoption.
* [Operations Manual](./operations.md) — Day-2 operations: metrics, alerting, SLOs, log schema, telemetry pipelines, incident handling.
* [Systemd Service Guide](./systemd-service.md) — Hardened unit files, journal integration, auto-restart strategies, controlled rollout.
* [Docker & Local Sandbox](./docker-local.md) — Container-based development environment, Compose topology, troubleshooting.

## 4. Governance, Compliance, and Community

* [Velocity Governance](../GOVERNANCE.md) — Maintainer roles, approval workflow, security review cadence.
* [Contribution Guidelines](../CONTRIBUTING.md) — Coding standards, review expectations, CI requirements.
* [Security Policy](../SECURITY.md) — Vulnerability disclosure instructions, triage SLAs, signing keys.
* [Roadmap](../ROADMAP.md) — Release milestones, spec revisions, adoption programs.

## 5. Specialized Guides

* [Deployment Appendix](./deployment.md#appendices) — Terraform snippets, Ansible roles, AWS/GCP/Azure reference architectures.
* [Upgrade Runbooks](./upgrade-guide.md#runbooks) — Stepwise procedures for each supported version family.
* [Troubleshooting Matrices](./user-handbook.md#troubleshooting) — Symptom-driven diagnosis for handshake failures, performance regressions, certificate alarms.
* [CA Operations](./ca-operations.md) — Velocity CA issuance workflows, ACME extensions, certificate transparency integration.
* [Formal Verification Notes](../spec/formal/README.md) — Summaries of Tamarin/ProVerif models, proof obligations, coverage.

## 6. How to use this hub

1. **Start with the User Handbook** to get a mental model of the CLI and config. The handbook links directly to quickstart scripts and sandbox environments.
2. **Pick a track** (operations, security, integration, developer) and follow recommended reading order within each track.
3. **Document readiness checklists** from each guide roll up into [`docs/troubleshooting.md`](./user-handbook.md#readiness-checklists) so you can validate pilot readiness.
4. **Bookmark status dashboards** described in [`docs/operations.md`](./operations.md#observability) to continuously watch downgrade ratios, PQ validation failures, and handshake latency.

> **Tip:** Every document in this site begins with a change-log section summarizing the last three revisions. Link directly to anchors like `#configuration-matrix` to embed Velocity guidance into your internal docs.

If a topic is missing, open an issue tagged `docs` with the expected audience, outcomes, and timelines. Documentation is versioned alongside code—check commit history when preparing audits or compliance reviews.
