# VELO Governance

VELO is a collaborative effort to produce a production-quality reference implementation of PQ-QUIC. This document outlines the maintainer structure, decision-making process, and release management expectations.

## Maintainer roles

| Role | Responsibilities | Current assignee |
| ---- | ---------------- | ---------------- |
| Lead network engineer | Transport design, congestion control, interoperability | @net-loop |
| Lead cryptographer | Hybrid handshake, KEM/signature integrations, formal proofs | @crypto-curve |
| Release manager | Roadmap coordination, CI/CD, release notes | @ship-it |
| Documentation steward | Specs, developer docs, governance artefacts | @doc-loop |

Maintainers are appointed by consensus and may delegate tasks to trusted contributors. New maintainers are added via a majority vote and must accept the security disclosure responsibilities laid out in `SECURITY.md`.

## Decision process

- **Rough consensus** – design changes follow IETF-inspired rough consensus, documented via GitHub issues/PRs referencing the spec.
- **Request for comments (RFC)** – protocol or API changes require an RFC in `docs/rfcs/` (submit as PR) with at least two maintainer approvals.
- **Security reviews** – any change affecting cryptography, handshake logic, or key material requires sign-off from the Lead cryptographer and Release manager.
- **Tie-breaking** – the Lead network engineer coordinates discussions and may escalate to a full maintainer vote if consensus stalls.

## Meetings & cadence

- Fortnightly sync to review roadmap progress, blockers, and interoperability feedback.
- Quarterly public roadmap update (see `ROADMAP.md`).
- Security incident postmortems are published within 30 days of disclosure.

## Release policy

- Semantic versioning (`MAJOR.MINOR.PATCH`).
- Every tagged release includes:
  - Changelog entry summarising features, bug fixes, and security notes.
  - Benchmark snapshots in `benchmarks/results/`.
  - Updated spec version with change log appendix.
- Release candidates (RC) are cut two weeks before targeted release date for ecosystem testing.

## Maintainer expectations

- Be responsive to issues/PRs (aim for initial response within two business days).
- Uphold the contribution checklist and enforce CI requirements.
- Champion documentation completeness alongside code correctness.
- Foster an inclusive, respectful community per the Code of Conduct.

## Escalation

- Security escalations follow `SECURITY.md`.
- Process or governance concerns can be raised by opening an issue tagged `governance` or by emailing `governance@velo.dev`.

We welcome additional stewards as the project matures—see `CONTRIBUTING.md` for how to get involved.
