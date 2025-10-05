# Running Velocity with systemd

This guide explains how to configure Velocity so that it automatically restarts after failures or reboots on Linux distributions that use `systemd`.

## 1. Install the Velocity binary

Copy the release binary (or the one you built from source) into a system-wide location, for example:

```bash
sudo install -m 0755 target/release/velocity /usr/local/bin/velocity
```

Ensure the runtime user (e.g. `www-data`) can read the site directory and certificates.

## 2. Create the working directory

```bash
sudo mkdir -p /var/www/velocity
sudo chown www-data:www-data /var/www/velocity
```

Place your static assets under this directory or adjust the paths below to match your deployment.

## 3. Drop-in service unit

A reference unit file lives at `deployment/systemd/velocity.service`. Copy it into place:

```bash
sudo cp deployment/systemd/velocity.service /etc/systemd/system/velocity.service
```

The file runs `velocity serve` with useful defaults:

- Binds the Velocity transport to `0.0.0.0:4433`.
- Serves files from `/var/www/velocity`.
- Enables the HTTPS preview listener on `8443`.
- Exposes Prometheus metrics on `127.0.0.1:9300`.
- Restarts automatically on crash (`Restart=always`).

Feel free to tweak `ExecStart` arguments (e.g. `--proxy`, `--config`, or `--domain`).

## 4. Reload systemd and enable the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable velocity.service
sudo systemctl start velocity.service
```

Velocity will now launch at boot and restart after crashes. Check status and logs with:

```bash
systemctl status velocity.service
journalctl -u velocity.service -f
```

## 5. Metrics and health checks

When `--metrics-listen` is provided, the CLI starts a Prometheus exporter. Scrape `http://127.0.0.1:9300/metrics` to collect counters for request volume, response sizes, and active sessions. You can integrate this endpoint with Prometheus, Grafana Agent, or any system that understands the OpenMetrics text format.

## 6. Graceful shutdown

`systemctl stop velocity.service` sends `SIGINT`, giving the server a chance to close existing connections, shut down the HTTPS preview listener, and flush telemetry before exiting. This mirrors the manual Ctrl+C workflow during development.

## 7. Troubleshooting tips

- If you see `Bind` errors, ensure no other process is using the same UDP/TCP ports.
- For TLS, either provide `--cert`/`--key`, enable `--self-signed`, or configure the ACME automation once Stage 3 lands.
- To run multiple instances, copy the unit file, adjust ports, and change the `WorkingDirectory` per instance.
