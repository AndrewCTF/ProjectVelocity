# Velocity Deployment Guide

> Step-by-step practices for launching Velocity in lab, pilot, and production environments. Covers network architecture, certificate automation, high availability, and platform-specific checklists.

---

## Change log

| Date | Revision | Highlights |
|------|----------|------------|
| 2025-10-06 | 1.0 | Comprehensive rewrite covering simplified configs, HA topologies, and certificate automation. |

## 1. Deployment patterns

Velocity can be deployed in three canonical topologies:

1. **Standalone edge** — Velocity terminates UDP/443 directly, serves static content or proxies upstreams. Great for pilots and edge micro-sites.
2. **Sidecar behind HTTPS front door** — Nginx/Envoy handles browser TLS, Velocity handles PQ transport for supporting clients. Downgrades stay transparent to end users.
3. **Anycast edge network** — Multiple PoPs running Velocity behind QUIC-aware load balancers or XDP-based dispatch, with central ticket key distribution.

Pick the topology that matches your risk tolerance, reach, and operational maturity.

## 2. Prerequisites

* Linux kernel ≥5.15 with UDP GRO enabled (`sysctl net.ipv4.udp_rmem_min=16384`).
* Systemd 249+ or container orchestrator (Kubernetes 1.28+).
* Access to UDP/443 through perimeter firewalls.
* Hybrid certificate (Dilithium + ECDSA) issued by Velocity CA or your internal CA. Self-signed acceptable for pilots.
* DNS entries for Velocity endpoints, plus HTTPS/SVCB records for ECH if enabled.

## 3. Installation checklist

1. **Create service account** on host: `useradd --system --home /var/lib/velocity velocity`.
2. **Install binaries**: copy `velocity-cli`, `velocity-server`, etc., into `/usr/local/bin`.
3. **Create directories**:
    * `/var/lib/velocity` — runtime state (tickets, caches).
    * `/etc/velocity` — configuration files (`serve.simple.yaml`, `edge.yaml`).
    * `/var/log/velocity` — log directory (if not using journald).
4. **Generate or install certificates** (see Section 5).
5. **Deploy systemd unit** from [`docs/systemd-service.md`](./systemd-service.md) or configure container manifest.

## 4. Simplified config example (balanced profile)

```yaml
server:
   listen: "0.0.0.0:4433"
   tls:
      certificate: "/etc/velocity/certs/fullchain.pem"
      private_key: "/etc/velocity/certs/privkey.pem"
      require_ech: false
   profiles:
      default: balanced
      permit: [light, balanced, secure]
   telemetry:
      metrics_listen: "127.0.0.1:9300"
      structured_logs: true
content:
   sites:
      - hostname: example.com
         root: "/srv/www/example"
         index: index.html
         cache_control: public, max-age=60
   proxies:
      - hostname: api.example.com
         upstream: "http://127.0.0.1:8080"
         preserve_host: true
         timeouts:
            connect: 5s
            response: 45s
            idle: 2m
tickets:
   max_age: 24h
   rotate_after: 12h
   storage: "/var/lib/velocity/tickets.json"
```

Store this as `/etc/velocity/serve.simple.yaml`. The CLI watches the file and hot-reloads changes.

## 5. Certificate automation

### Using Certbot with Velocity hooks

1. Install Certbot and DNS plugin (e.g., `certbot-dns-cloudflare`).
2. Issue certificate:

    ```pwsh
    sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.secrets/cloudflare.ini \
       -d example.com -d *.example.com
    ```

3. Convert to hybrid certificate using Velocity CA helper:

    ```pwsh
    velocity-cli cert hybridize \
       --chain /etc/letsencrypt/live/example.com/fullchain.pem \
       --key /etc/letsencrypt/live/example.com/privkey.pem \
       --out /etc/velocity/certs
    ```

4. Install renewal hook `/etc/letsencrypt/renewal-hooks/post/velocity.sh`:

    ```bash
    #!/bin/bash
    set -euo pipefail
    velocity-cli cert hybridize \
       --chain "/etc/letsencrypt/live/$RENEWED_DOMAINS/fullchain.pem" \
       --key "/etc/letsencrypt/live/$RENEWED_DOMAINS/privkey.pem" \
       --out /etc/velocity/certs
    systemctl reload velocity.service
    ```

5. Test renewal: `sudo certbot renew --dry-run`.

### Issuing with Velocity CA

See [`docs/ca-operations.md`](./ca-operations.md) for ACME workflows, CSR formats, and policy enforcement.

## 6. Network integration

### Nginx front door (HTTPS + Velocity sidecar)

1. Configure Nginx to terminate TLS on TCP/443 for browsers (see sample config in README context).
2. Proxy HTTP traffic to Velocity via localhost HTTP port or direct static assets depending on site structure.
3. Forward UDP/443 to Velocity using `stream` block with QUIC support (Nginx 1.25+ compiled with `--with-stream_quic_module`). Example:

    ```nginx
    stream {
       upstream velocity_udp {
          server 127.0.0.1:4433 udp;
       }

       server {
          listen 443 udp reuseport;
          proxy_pass velocity_udp;
       }
    }
    ```

4. Ensure firewall permits UDP/443. On Ubuntu: `ufw allow 443/udp`.

### Envoy edge proxy

* Use QUIC listener with UDP forward cluster to Velocity.
* Configure ALPN filter chain to allow `velocity/1` and `h3` simultaneously.

### Kubernetes deployment

1. Deploy Velocity as a Deployment with `hostNetwork: true` or using `NodePort` for UDP/443.
2. For L4 load balancing, use MetasLB, Cilium, or cloud UDP LB support (GCP Load Balancer, AWS NLB with UDP).
3. Mount certificates via `Secret` volumes. Reconcile via cert-manager with custom issuer for hybrid certs.

## 7. High availability

* **Active-active**: Multiple Velocity nodes behind QUIC-aware LB. Share ticket keys via secret management service. Use Redis or etcd to distribute admin API state if enabling connection migration across nodes.
* **Active-passive**: Secondary node in hot standby. Use `velocity-cli admin replicate` to sync ticket state and configuration.
* **State sync**: Optional gRPC-based control plane (`velocity-control`) replicates policy decisions, including rate limits and telemetry toggles.

## 8. Operations lifecycle

### Rolling upgrade procedure

1. Label node as draining using `velocity-cli admin quiesce`.
2. Wait for `active_connections` metric to drop below threshold.
3. Deploy new binary (RPM/DEB/Container) and restart service.
4. Validate health via `velocity-cli health`. Ensure `downgrade_events_total` remains stable.
5. Resume traffic with `velocity-cli admin resume`.

### Backup strategy

* Backup `/etc/velocity`, `/var/lib/velocity`. Version control configs in Git.
* Store encrypted copies of ticket secrets and certificate private keys in a secure vault (HashiCorp Vault, AWS KMS).

### Disaster recovery

1. Re-provision host using infrastructure automation.
2. Restore configs and secrets from backup.
3. Rehydrate ticket keys if available; otherwise, expire outstanding tickets.
4. Validate connectivity using `velocity-cli client probe`.

## 9. Platform-specific notes

### Windows pilots

* Deploy Velocity inside WSL2, bind to `0.0.0.0:4433`, and expose UDP port using `netsh interface portproxy` (limited performance) or run on Hyper-V Linux VM.
* Use `New-NetFirewallRule -DisplayName "Velocity UDP" -Direction Inbound -Protocol UDP -LocalPort 443`.

### macOS developer setup

* Use Homebrew formula (see `docs/docker-local.md`). macOS lacks systemd; rely on `launchd` plist in `docs/assets/launchd/velocity.plist`.

### Cloud providers

* **AWS** — Use Network Load Balancer (UDP listener). Attach Auto Scaling group with Velocity AMI. Use Systems Manager for secret rotation.
* **GCP** — Configure Cloud Load Balancing with UDP proxy. Cloud Armor policies for DDoS.
* **Azure** — Employ Azure Front Door Premium with UDP custom domain, or use Azure Load Balancer.

## 10. Appendices

* [Appendix A: Terraform modules](./deployment.md#appendix-a-terraform)
* [Appendix B: Ansible role snippet](./deployment.md#appendix-b-ansible)
* [Appendix C: Edge runtime schema](./deployment.md#appendix-c-edge-runtime-schema)

git clone https://github.com/projectvelocity/velocity.git
cargo run -p velocity-cli --bin velocity -- serve --root public --self-signed --listen 0.0.0.0:4433
git clone https://github.com/velocity-protocol/velocity.git
Each appendix contains copy-paste ready infrastructure snippets maintained alongside integration tests.

### Appendix A — Terraform module sketch <a id="appendix-a-terraform"></a>

```hcl
module "velocity_edge" {
   source              = "./terraform/modules/velocity-edge"
   name                = "velocity-prod"
   region              = var.region
   listen_udp_port     = 443
   certificate_secret  = aws_secretsmanager_secret.velocity_cert.arn
   ticket_secret_arn   = aws_kms_key.velocity_ticket.arn
   instance_count      = 3
   instance_type       = "c7g.large"
   security_group_ids  = [aws_security_group.velocity.id]
   enable_observability = true
}
```

### Appendix B — Ansible role snippet <a id="appendix-b-ansible"></a>

```yaml
- name: Deploy Velocity
   hosts: velocity
   become: true
   roles:
      - role: velocity
         vars:
            velocity_version: "latest"
            velocity_listen: "0.0.0.0:4433"
            velocity_cert_path: "/etc/velocity/certs/fullchain.pem"
            velocity_key_path: "/etc/velocity/certs/privkey.pem"
            velocity_config_template: "templates/serve.simple.yaml.j2"
            velocity_metrics_listen: "127.0.0.1:9300"
```

### Appendix C — Edge runtime schema <a id="appendix-c-edge-runtime-schema"></a>

```yaml
templates_dir: templates
middlewares:
   - name: auth
      kind: oidc
      issuer: https://auth.example.com
      client_id: velocity-edge
rate_limit:
   limit: 120
   window: 1m
routes:
   - match:
         path: /healthz
         methods: [GET]
      action:
         type: static
         status: 200
         body: "ok"
   - match:
         path: /api
      action:
         type: proxy
         upstream: http://127.0.0.1:4000
         streaming: true
```

Use the schema alongside the simplified config to compose advanced behaviours without modifying Rust code.
- `ClientConfig::with_alpns` – set client ALPN preference order.

## Fallback topology

```
         ┌────────────────┐
         │     Client     │
         └────────┬───────┘
            │
            │ Initial (velocity/1, h3)
            ▼
         ┌────────────────┐
         │ Velocity Frontend │
         │  (pqq-server)  │
         └────────┬───────┘
            │
        ┌────────────┴────────────┐
        │                           │
   Velocity session established        Fallback advisory
        │                           │
        ▼                           ▼
    Application handler          HTTP/3 or HTTPS origin
```

Velocity always sends an explicit fallback directive when the client and server
cannot agree on `velocity/1`. Out of the box the handshake driver advertises an
HTTP/3 (`h3`) target on UDP/TCP port 443 so browsers can downgrade straight to
TLS 1.3 + QUIC. If you need a classical TLS or even plain HTTP target instead,
override the ALPN and endpoint via `HandshakeConfig::with_fallback_endpoint` on
both the server and client configuration. For example, setting the fallback to
`http/1.1` or `h2` directs Velocity-aware clients to reconnect over HTTPS on the
host/port you publish. Pair that endpoint with a reverse proxy (NGINX, Envoy,
etc.) to bridge legacy HTTP/1.x traffic when required.

## Certificate strategy

- Pilot deployments can begin with classical certificates; hybrid cert ingestion is on the roadmap.
- For experimental runs, generate self-signed certs and configure browsers/clients to trust the root.
- Documented CSR formats and CA guidance will land alongside Dilithium support.

## Networking considerations

- Ensure UDP 443 is reachable through firewalls/NAT.
- Enable ECMP-friendly connection IDs once migration support lands.
- Set `SO_REUSEADDR` if running multiple instances on the same host (todo: expose binding helper).

## Observability

- Enable structured logging: `RUST_LOG=pqq_server=info,pqq_core=debug`.
- Planned: metrics exporters for handshake latency, fallback rate, and key schedule timings.

## Reverse proxy integration

VELO can sit behind an existing HTTP reverse proxy while terminating PQ-QUIC at the edge.

### NGINX stream pass-through

1. Terminate PQ-QUIC with `pqq-server` bound to `127.0.0.1:4443`.
2. Configure NGINX stream block to fan in UDP 443 traffic:
   ```nginx
   stream {
      upstream velo_udp {
         server 127.0.0.1:4443;
      }

      server {
         listen 443 udp reuseport;
         proxy_pass velo_udp;
         proxy_responses 1;
      }
   }
   ```
3. Enable the HTTP gateway (e.g., `examples/browser-gateway`) to translate browser traffic and relay to PQ-QUIC for legacy clients.

### Envoy/HAProxy pattern

- Use a dedicated UDP listener forwarding to the VELO server’s `SocketAddr`.
- Preserve DCIDs by enabling consistent hashing (Envoy `use_original_dst`, HAProxy `hash-type consistent`) to maintain connection stickiness.
- For dual-stack nodes, expose IPv6 + IPv4 listeners and forward to a single PQ-QUIC instance; the handshake teasing fallback metadata ensures HTTP/3 downgrade continues via the reverse proxy if needed.

## CDN edge pilot recipe

1. Deploy VELO nodes on the edge fleet (close to POPs) with UDP 443 open and HTTP/3 fallback endpoints reachable inside the CDN fabric.
2. Run the `handshake-demo` binary in CI/CD smoke tests to assert PQ/legacy downgrade before promoting a POP.
3. Export the hybrid handshake transcript via `examples/handshake-transcript-dump` and stash the JSON output alongside POP health metrics. This provides quick detection if PQ primitives drift across deployments.
4. Front the PQ-QUIC servers with your CDN load balancer in “UDP proxy” mode and reuse existing TLS cert automation for the fallback origin. The fallback endpoint advertised by VELO should resolve to a classic HTTP/3 cluster.
5. Monitor:
   - PQ accept rate vs. fallback rate.
   - Kyber encapsulation latency (derived from `pqq_server::metrics` once implemented).
   - UDP error counters or NAT binding churn to size state tables appropriately.

## Production readiness checklist (pre-v1)

- [ ] ML-KEM/ML-DSA integration complete.
- [ ] Session tickets with replay mitigation.
- [ ] Congestion control tuned for PQ overhead.
- [ ] CI coverage with sanitizers & fuzzers.
- [ ] Formal verification summary published.

This guide will expand with automation scripts and deployment manifests as the project matures.
