# Syslog Deduplication with NSX-T Lookup

A Python-based syslog server that receives firewall logs from VMware Log Insight, removes duplicates based on key fields, parses log lines, looks up source/destination IP groups in NSX-T Manager, and forwards processed logs to another syslog server.

## Features

- Receives syslog messages via UDP port 514
- Parses firewall log format from VMware Log Insight
- Deduplicates logs based on key fields (source IP, destination IP, ports, protocol)
- Looks up IP addresses in NSX-T Manager to find corresponding groups
- Forwards enriched logs to a downstream syslog server

## Installation

1. Install Python 3.8 or higher
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Create a `config.yaml` file in the project root with the following structure:

```yaml
syslog:
  listen_port: 514
  forward_host: "downstream-syslog.example.com"
  forward_port: 514
  # Set to true to forward to downstream syslog over TCP instead of UDP
  use_tcp: false

nsxt:
  host: "nsxt-manager.example.com"
  username: "admin"
  password: "password"
  verify_ssl: true
  cache_ttl: 3600  # Cache group lookups for 1 hour

influx:
  enabled: false  # Set to true to enable InfluxDB v1 writes
  host: "localhost"
  port: 8086
  database: "firewall"
  username: ""
  password: ""
  measurement: "firewall_logs"

postgres:
  enabled: false  # Set to true to enable PostgreSQL writes
  host: "localhost"
  port: 5432
  database: "firewall"
  user: "firewall_user"
  password: "password"
  table: "flows"
```

Alternatively, you can use environment variables:
- `SYSLOG_LISTEN_PORT` (default: 514)
- `SYSLOG_FORWARD_ENABLED` (default: true; set to `false` to disable downstream forwarding)
- `SYSLOG_FORWARD_HOST` (required when forwarding enabled)
- `SYSLOG_FORWARD_PORT` (default: 514)
- `SYSLOG_FORWARD_USE_TCP` (default: false)
- `NSXT_HOST` (required)
- `NSXT_USERNAME` (required)
- `NSXT_PASSWORD` (required)
- `NSXT_VERIFY_SSL` (default: true)
- `INFLUX_ENABLED` (default: false)
- `INFLUX_HOST` (default: localhost)
- `INFLUX_PORT` (default: 8086)
- `INFLUX_DB` (required if Influx enabled)
- `INFLUX_USERNAME` (optional)
- `INFLUX_PASSWORD` (optional)
- `INFLUX_MEASUREMENT` (default: firewall_logs)
- `PG_ENABLED` (default: false)
- `PG_HOST` (default: localhost)
- `PG_PORT` (default: 5432)
- `PG_DB` (required if Postgres enabled)
- `PG_USER` (required if Postgres enabled)
- `PG_PASSWORD` (optional)
- `PG_TABLE` (default: flows)
- `WEB_ONLY` (set to `true` to run only the web UI, without syslog/NSXT config)
- `WEB_HOST` (default: 0.0.0.0)
- `WEB_PORT` (default: 8080)
- `WEB_BASE_PATH` (optional; e.g. `/syslogdedup` when the UI is served under an ingress subpath; no trailing slash)
- `OIDC_ENABLED` (default: false)
- `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI` (required when OIDC enabled)
- `OIDC_SCOPE` (optional)
- `OIDC_SESSION_SECRET` or `WEB_SESSION_SECRET` (required when OIDC enabled)

## Docker

Two images are provided: **web UI** ([`Dockerfile.web`](Dockerfile.web)) and **syslog receiver** ([`Dockerfile.syslog`](Dockerfile.syslog)).

### Build

```bash
docker build -f Dockerfile.web -t syslogdedup-web .
docker build -f Dockerfile.syslog -t syslogdedup-syslog .
```

### Web UI with Compose (Postgres + app)

1. Copy [`.env.example`](.env.example) to `.env` and set `POSTGRES_PASSWORD` (and optional `WEB_PUBLISH_PORT`).
2. Start:

   ```bash
   docker compose up --build -d
   ```

3. Open `http://localhost:8080/` (or the host port you mapped).

Set OIDC and other settings via environment variables on the `web` service (see below). **`OIDC_REDIRECT_URI`** must be the public URL users use to reach the app (e.g. `https://your-host/auth/callback`), matching Keycloak **Valid redirect URIs**.

**Subpath (`WEB_BASE_PATH`):** When set, the app is also mounted at that URL path (e.g. `WEB_BASE_PATH=/app` → UI at `https://host/app/`). The UI and API calls use the same prefix. Set **`OIDC_REDIRECT_URI`** to the full callback URL including the path (e.g. `https://host/app/auth/callback`). You can either route that path to this service in your ingress or rely on the in-app mount without rewriting the path.

### Run web image without Compose

```bash
docker run --rm -p 8080:8080 \
  -e WEB_ONLY=true \
  -e PG_ENABLED=true \
  -e PG_HOST=your-postgres-host \
  -e PG_DB=firewall -e PG_USER=firewall -e PG_PASSWORD=secret \
  syslogdedup-web
```

### Syslog receiver image

Runs `python main.py`. Map the **UDP** listen port (default 514; ports &lt;1024 often need root—the syslog image runs as root for that reason, or set `SYSLOG_LISTEN_PORT` to e.g. `1514` and map `1514:1514/udp`).

```bash
docker run --rm \
  -p 514:514/udp \
  -e SYSLOG_FORWARD_HOST=downstream.example.com \
  -e NSXT_HOST=nsxt.example.com \
  -e NSXT_USERNAME=admin -e NSXT_PASSWORD=secret \
  syslogdedup-syslog
```

Optional: `docker compose --profile syslog up` starts the **syslog** service from [`docker-compose.yml`](docker-compose.yml); set `SYSLOG_FORWARD_HOST`, `NSXT_*`, and optionally Postgres-related vars if `SYSLOG_PG_ENABLED=true`.

### Kubernetes

Manifests live under [`k8s/`](k8s/). Typical flow:

1. Build and push images (e.g. `syslogdedup-web`, `syslogdedup-syslog`) to your registry.
2. Edit [`k8s/web-deployment.yaml`](k8s/web-deployment.yaml) `image:` to your registry/tags.
3. Copy [`k8s/secret.example.yaml`](k8s/secret.example.yaml) to `k8s/secret.yaml`, set `postgres-password` (and OIDC or `nsxt-password` if needed). `k8s/secret.yaml` is gitignored.
4. Apply Secret, then the rest:

   ```bash
   kubectl apply -f k8s/secret.yaml
   kubectl apply -k k8s/
   ```

5. Optional HTTP ingress: edit and apply [`k8s/web-ingress.yaml`](k8s/web-ingress.yaml) (`ingressClassName`, host, TLS). Set `OIDC_REDIRECT_URI` to match the public URL (e.g. `https://<ingress-host>/auth/callback`).
6. Optional UDP syslog: uncomment syslog resources in [`k8s/kustomization.yaml`](k8s/kustomization.yaml), configure [`k8s/syslog-deployment.yaml`](k8s/syslog-deployment.yaml), ensure Secret contains `nsxt-password`, push `syslogdedup-syslog` image.

## Usage

Run the syslog server:

```bash
python main.py
```

Note: Binding to port 514 typically requires root/sudo privileges on Linux systems.

### Web UI (firewall rules)

If PostgreSQL is enabled, you can run a read-only web UI to list firewall rules, filter by source/dest group, and use clickable ports for future NSX-T rule injection:

```bash
# With PG_* env or config set, and WEB_ONLY so syslog/NSXT are not required:
WEB_ONLY=true uvicorn web:app --host 0.0.0.0 --port 8080
```

Open `http://localhost:8080/`. Use the dropdowns to filter by **Source group** and **Dest group**. Rules are grouped by (source_group, dest_group). Click a port to use it later for injecting rules into NSX-T Manager.

### OIDC login (Keycloak)

Optional. When `oidc.enabled` is true in `config.yaml` (or `OIDC_ENABLED=true`), the UI and API require a signed session cookie after login via Keycloak.

Configure in `config.yaml` (see `config.yaml.example`) or environment variables:

| Variable | Meaning |
|----------|---------|
| `OIDC_ENABLED` | `true` to enable |
| `OIDC_ISSUER` | Realm issuer URL, e.g. `https://keycloak.example.com/realms/myrealm` |
| `OIDC_CLIENT_ID` | Confidential client ID |
| `OIDC_CLIENT_SECRET` | Client secret |
| `OIDC_REDIRECT_URI` | Full callback URL; must match Keycloak **Valid redirect URIs** exactly (e.g. `https://your-host/auth/callback`) |
| `OIDC_SCOPE` | Optional; default `openid email profile` |
| `OIDC_SESSION_SECRET` | Long random string used to sign the session cookie (or `WEB_SESSION_SECRET`) |

In Keycloak: create a **confidential** client, enable **Standard flow**, set the redirect URI to the same value as `OIDC_REDIRECT_URI`, and copy the client secret.

When OIDC is enabled, the home page loads without redirect; use **Log in** to start the Keycloak flow. Without a session, `/api/*` returns 401. Public paths include `/`, `/api/auth/status`, `/auth/*`, and `/static/*`.

## Log Format

The parser expects firewall logs in the following format:
```
<timestamp/id> <network_type> <action> <result> <rule_id> <direction> <size/id> <protocol> <source_ip/port>-><dest_ip/port> <rule_name>
```

Example:
```
7c11f001 INET match PASS 8225 OUT 73 UDP 10.10.10.10/42017->20.20.20.20/53 SZ-TRF_CATCH_ALL1111_TFRC6-6_Server_B
```

## Architecture

The system processes logs through the following pipeline:
1. Receive syslog message via UDP
2. Parse log line to extract structured fields
3. Check for duplicates based on key fields
4. Lookup source and destination IP groups in NSX-T Manager
5. Enrich log with group information
6. Forward to downstream syslog server

