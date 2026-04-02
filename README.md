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
- `SYSLOG_FORWARD_HOST` (required)
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
- `OIDC_ENABLED` (default: false)
- `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI` (required when OIDC enabled)
- `OIDC_SCOPE` (optional)
- `OIDC_SESSION_SECRET` or `WEB_SESSION_SECRET` (required when OIDC enabled)

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

Paths without login: `/auth/login`, `/auth/callback`, `/auth/logout`, and `/static/*`. All other routes (including `/`, `/api/*`, `/docs`) require authentication.

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

