"""InfluxDB v1 client for writing firewall flow logs."""
import logging
import time
from typing import Optional, List

import requests

from config import InfluxConfig
from parser import ParsedLog


logger = logging.getLogger(__name__)


class InfluxClient:
    """Simple InfluxDB v1 line protocol writer."""

    def __init__(self, config: InfluxConfig):
        """
        Initialize InfluxDB client.

        Args:
            config: InfluxConfig with connection details
        """
        self.config = config
        self.session = requests.Session()

        scheme = "http"
        self.base_url = f"{scheme}://{config.host}:{config.port}"

    def _build_line(
        self,
        log: ParsedLog,
        src_groups: Optional[List[str]] = None,
        dest_groups: Optional[List[str]] = None,
    ) -> str:
        """
        Build InfluxDB line protocol for a single log entry.

        Tags (indexed in Influx):
          - src_ip
          - src_group
          - dest_ip
          - dest_group
          - protocol

        Fields:
          - src_port (int)
          - dest_port (int)
          - rule_id (string)
          - rule_name (string)
          - direction (string)
          - action (string)
          - result (string)
        """
        # Tags: escape spaces and commas
        def esc_tag(v: str) -> str:
            return v.replace(" ", r"\ ").replace(",", r"\,")

        src_group = src_groups[0] if src_groups else ""
        dest_group = dest_groups[0] if dest_groups else ""

        measurement = self.config.measurement

        tags = [
            f"src_ip={esc_tag(log.source_ip)}",
            f"dest_ip={esc_tag(log.dest_ip)}",
            f"protocol={esc_tag(log.protocol)}",
        ]
        if src_group:
            tags.append(f"src_group={esc_tag(src_group)}")
        if dest_group:
            tags.append(f"dest_group={esc_tag(dest_group)}")

        # Fields: strings must be quoted, ints plain
        # Pre-escape quotes in strings to avoid f-string backslash issues
        rule_id_escaped = log.rule_id.replace('"', '\\"')
        rule_name_escaped = log.rule_name.replace('"', '\\"')

        fields = [
            f"src_port={int(log.source_port)}i",
            f"dest_port={int(log.dest_port)}i",
            f'rule_id="{rule_id_escaped}"',
            f'rule_name="{rule_name_escaped}"',
            f'direction="{log.direction}"',
            f'action="{log.action}"',
            f'result="{log.result}"',
        ]

        # Use current time in nanoseconds
        ts_ns = int(time.time() * 1_000_000_000)

        line = f"{measurement},{','.join(tags)} {','.join(fields)} {ts_ns}"
        return line

    def write_log(
        self,
        log: ParsedLog,
        src_groups: Optional[List[str]] = None,
        dest_groups: Optional[List[str]] = None,
    ) -> bool:
        """
        Write a single log entry to InfluxDB.

        Args:
            log: ParsedLog instance
            src_groups: Selected source groups (names)
            dest_groups: Selected destination groups (names)

        Returns:
            True on success, False on failure.
        """
        if not self.config.enabled:
            return True

        line = self._build_line(log, src_groups, dest_groups)

        params = {"db": self.config.database, "precision": "ns"}
        url = f"{self.base_url}/write"

        auth = None
        if self.config.username:
            auth = (self.config.username, self.config.password or "")

        try:
            resp = self.session.post(
                url,
                params=params,
                data=line.encode("utf-8"),
                auth=auth,
                timeout=5,
            )
            if resp.status_code >= 300:
                logger.warning(
                    "Failed to write to InfluxDB: status=%s body=%s",
                    resp.status_code,
                    resp.text[:200],
                )
                return False
            return True
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error writing to InfluxDB: {e}")
            return False


