# Velocity Upgrade Guide

This guide describes the recommended steps for moving from Velocity **v0.1.x** to **v0.2.0**. It covers preparation, rollout sequencing, validation, and post-upgrade benchmarking so operators can adopt the new edge runtime features and performance improvements with minimal risk.

---

## 1. Summary of Changes in 0.2.0

- **Edge Runtime Promotion**: `velocity-edge` now ships as a first-class runtime with WAF, rate limiting, templating, and FastAPI-style routing. The CLI exposes `--edge-config` for declarative enablement.
- **Documentation Overhaul**: Comprehensive user handbook, docs hub, and upgrade guide (this document).
- **Security Enhancements**: Default security headers, updated WAF rules, and improved fallback telemetry.
- **Performance Improvements**: Optimized handshake path and middleware pipeline (see updated benchmarks in `docs/benchmarking.md`).

Ensure you review the full release notes in `CHANGELOG.md` before upgrading production environments.

---

## 2. Pre-Upgrade Checklist

1. **Inventory Deployments**: List all nodes running Velocity 0.1.x (CLI, server embeddings, edge experiments).
2. **Export Configuration**:
   - Static site roots and indices.
   - Reverse proxy flags (`--proxy-*`).
   - Any experimental `edge.yaml` files.
3. **Snapshot Certificates**: Back up PEM chains and private keys.
4. **Benchmark Baseline**: Run `cargo bench -p handshake-bench -- --sample-size 20 --noplot` on a representative machine and archive results for comparison.
5. **Staging Environment**: Prepare a staging cluster mirroring production topology.

---

## 3. Upgrade Procedure

1. **Fetch Release Artifacts**
   - Download the v0.2.0 binaries from the releases page or build from source:
     ```pwsh
     git fetch --tags
     git checkout v0.2.0
     cargo build --release --workspace
     ```
2. **Roll Out to Staging**
   - Replace binaries on staging nodes.
   - Run smoke tests:
     ```pwsh
     velocity --version
     velocity serve --root public --dry-run # validates config only
     cargo run -p pqq-client --example velocity-fetch -- 127.0.0.1:4443 https://localhost/
     ```
   - Enable edge runtime if required:
     ```pwsh
     velocity serve --root public --edge-config edge.yaml -vv
     ```
3. **Validate Compatibility**
   - Confirm ALPN fallback to `h3` still functions using legacy clients.
   - Inspect logs for WAF or rate-limit rejections; tune `edge.yaml` as needed.
4. **Deploy to Production**
   - Use rolling or blue/green strategy. For each node:
     1. Drain traffic or remove from load balancer.
     2. Install new binary and configuration.
     3. Run `velocity --version` to confirm v0.2.0.
     4. Rejoin node to traffic pool after health checks pass.
5. **Post-Deployment Verification**
   - Monitor handshake success rate, latency, fallback frequency.
   - Compare new benchmark numbers with baseline (see Section 4).

---

## 4. Post-Upgrade Benchmarking

1. Run the Criterion suite:
   ```pwsh
   cargo bench -p handshake-bench -- --sample-size 20 --noplot
   ```
2. Update `benchmarks/results/*.csv` with the latest output.
3. Record hardware, OS version, `rustc --version`, and commit hash.
4. Compare with the baseline tables in `docs/benchmarking.md` to verify improvements.

---

## 5. Rollback Plan

If issues arise:

1. Replace v0.2.0 binaries with the previous 0.1.x build (keep backups handy).
2. Revert configuration changes (especially `edge.yaml`).
3. Confirm downgrade via `velocity --version`.
4. File an incident report including logs, reproduction steps, and benchmark deltas.

---

## 6. Frequently Asked Upgrade Questions

- **Does the edge runtime run by default?**
  No. `--edge-config` must be supplied explicitly. Without it, Velocity behaves like the 0.1.x static server/proxy.

- **Are new ports required?**
  No. Velocity continues to operate on UDP 443/4433. The edge runtime reuses existing listeners.

- **Do I need to regenerate certificates?**
  Not unless you opt into new signature algorithms. Existing hybrid certs remain valid.

- **Can I mix 0.1.x and 0.2.x nodes?**
  Temporarily, yes. However, finish the rollout promptly to avoid configuration drift and take advantage of the new features.

---

## 7. Support & Reporting

- For upgrade assistance, file issues on GitHub with the `upgrade` label.
- Security-related problems should follow the disclosure process in `SECURITY.md`.
- Enterprise customers can schedule upgrade office hours as described in `docs/governance.md`.

Happy upgrading! Let us know how the transition went and what else would help streamline future releases.
