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

nsxt:
  host: "nsxt-manager.example.com"
  username: "admin"
  password: "password"
  verify_ssl: true
  cache_ttl: 3600  # Cache group lookups for 1 hour
```

Alternatively, you can use environment variables:
- `SYSLOG_LISTEN_PORT` (default: 514)
- `SYSLOG_FORWARD_HOST` (required)
- `SYSLOG_FORWARD_PORT` (default: 514)
- `NSXT_HOST` (required)
- `NSXT_USERNAME` (required)
- `NSXT_PASSWORD` (required)
- `NSXT_VERIFY_SSL` (default: true)

## Usage

Run the syslog server:

```bash
python main.py
```

Note: Binding to port 514 typically requires root/sudo privileges on Linux systems.

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

