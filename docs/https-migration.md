# Migrating from legacy HTTPS stacks to Velocity

Velocity bundles a post-quantum transport, hybrid TLS preview listener, static-site tooling, and reverse proxy features into a single binary. This guide walks through the practical steps to migrate from a traditional setup (e.g. Caddy or Nginx in front of Velocity) to a unified deployment driven by `velocity-cli`.

## Why consolidate?

Many early adopters ran Velocity alongside an existing HTTPS server. The TCP stack terminated legacy browsers, handled ACME, and reverse-proxied into the Velocity UDP listener. That architecture worked, but it doubled the operational surface area. Operators had to manage two sets of logs, two watchdog services, and two sources of truth for routing rules. Stage 4 of the HTTPS roadmap closes that gap: the CLI now exposes structured logging, a Prometheus metrics exporter, and sharp defaults that mirror Caddy's ergonomics. This lets most teams remove the extra hop entirely.

Key benefits of the built-in pipeline:

- **Consistent observability** – tracing spans and Prometheus counters cover both Velocity QUIC and HTTPS preview requests, giving you a single dashboard.
- **Simpler automation** – the CLI exposes the same flags (`--domain`, `--email`, `--accept-tos`) that administrators already expect from Caddy-like tools.
- **Predictable restarts** – the reference systemd unit keeps the process alive across reboots without auxiliary scripts.

## Step 1: audit current traffic

Before cutting over, catalogue the domains and routes your legacy HTTPS server handles. If you're using host-based routing, migrate the mapping into a Velocity serve configuration file or edge function. Validate that fallback behavior (e.g. HTTP/3 clients using ALPN `h3`) is acceptable using the `--fallback-alpn` and `--fallback-host` flags.

## Step 2: match CLI flags to your previous config

Velocity's CLI includes parity flags for common HTTPS workflows:

- `--domain` – sets the hostname baked into a self-signed certificate when `--self-signed` is enabled.
- `--email` and `--accept-tos` – record ACME account details ahead of Stage 3 automation. During Stage 4 they are stored for telemetry/logging and validate that operators provided consent.
- `--metrics-listen` – opens a Prometheus endpoint (for example `127.0.0.1:9300`) so observability tooling can scrape request counters and gauges. This replaces `caddy metrics` or Nginx's `stub_status` modules.

Combine these with existing flags such as `--proxy` or `--edge-config` to reproduce your topology. If you previously relied on HTTP→HTTPS redirects, enable `--serve-https` so the embedded preview listener can respond on TCP 8443 while your Velocity transport remains on UDP 4433.

## Step 3: enable metrics and structured logs

Operators typically tie deployment readiness to dashboards. Stage 4 introduces a telemetry module inside the CLI:

1. Start the server with `--metrics-listen 127.0.0.1:9300`.
2. Scrape `http://127.0.0.1:9300/metrics` and verify the presence of counters such as `velocity_http_requests_total` and `velocity_active_requests`.
3. Switch the log format to JSON with `--log-format json` (the default remains human-friendly text). The JSON stream integrates cleanly with Fluent Bit, Vector, or CloudWatch Logs.

Because telemetry spans both reverse proxy and static asset handlers, you can drop per-service exporters that were attached to your legacy server. The metrics surface includes method/status labels, response byte counts, and handshake tallies, giving you enough to drive SLO burn-rate alerts.

## Step 4: wire up systemd auto-start

Use the `deployment/systemd/velocity.service` unit file as a template. It launches `velocity serve` with HTTPS preview and metrics enabled, runs under a non-root user, and restarts automatically. After copying it into `/etc/systemd/system`, run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now velocity.service
```

This ensures Velocity returns after host reboots or process crashes. Compare that to the old split setup where you probably supervised Nginx/Caddy separately from the Velocity UDP daemon. Now a single unit covers both roles.

## Step 5: decommission the legacy HTTPS proxy

Once traffic flows through Velocity, disable the upstream proxy to avoid port conflicts. If you still need HTTP/3 fallback for clients that do not speak `velocity/1`, point `--fallback-host` at a managed CDN or a slimmed-down Nginx instance. The CLI logs whenever a request falls back so you can monitor how often legacy paths are exercised.

## Step 6: document operational runbooks

Update internal playbooks with the new commands:

- `velocity serve --metrics-listen 127.0.0.1:9300 --log-format json`
- `systemctl restart velocity.service`
- `curl -sf http://127.0.0.1:9300/metrics`

Also record the location of the Prometheus scraper configuration and Grafana dashboards that visualize the new metrics. Sharing these notes makes on-call handoffs smoother and prepares your team for the coming ACME automation in Stage 3.

## Step 7: prepare for automatic certificates

Even though Stage 3 (full ACME) is in progress, you can stage prerequisites now:

- Provide `--email` and `--accept-tos` so the CLI validates the operator has granted consent.
- Store self-signed or manually issued certificates under `/var/www/velocity/certs` and mount them with `--cert` / `--key` if you need production TLS immediately.
- Keep your DNS records pointed at the Velocity host; Stage 3 will recycle the same listener to serve HTTP-01 challenges.

## Cutover checklist

- [ ] Metrics endpoint reachable and scraped by Prometheus.
- [ ] JSON logs flowing into your preferred log aggregation pipeline.
- [ ] systemd unit enabled and stable after a reboot test.
- [ ] Fallback telemetry monitored (expect a short tail of legacy clients).
- [ ] Certificates present (self-signed or CA-issued) until the ACME flow lands.

By following the steps above, teams can collapse their dual-stack deployments into a single Velocity process without losing observability, restart guarantees, or configuration clarity. The Stage 4 improvements are designed to minimize surprises now and smooth the path toward the fully automated HTTPS story targeted for Stage 3.
