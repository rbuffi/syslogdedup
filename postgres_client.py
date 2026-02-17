"""PostgreSQL client for storing aggregated firewall flows."""
import logging
from typing import Optional, List

import psycopg2
from psycopg2.extras import execute_values

from config import PostgresConfig
from parser import ParsedLog


logger = logging.getLogger(__name__)


class PostgresClient:
    """Simple PostgreSQL client that writes per-flow rows suitable for Grafana."""

    def __init__(self, config: PostgresConfig):
        self.config = config
        self.conn = None
        if self.config.enabled:
            self._connect()
            self._ensure_table()

    def _connect(self):
        try:
            self.conn = psycopg2.connect(
                host=self.config.host,
                port=self.config.port,
                dbname=self.config.database,
                user=self.config.user,
                password=self.config.password,
            )
            self.conn.autocommit = True
            logger.info(
                "Connected to PostgreSQL at %s:%s db=%s",
                self.config.host,
                self.config.port,
                self.config.database,
            )
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            self.conn = None

    def _ensure_table(self):
        """Create the flows table if it doesn't exist."""
        if not self.conn:
            return
        sql = f"""
        CREATE TABLE IF NOT EXISTS {self.config.table} (
            id SERIAL PRIMARY KEY,
            ts TIMESTAMPTZ DEFAULT NOW(),
            src_ip TEXT NOT NULL,
            src_group TEXT,
            dest_ip TEXT NOT NULL,
            dest_group TEXT,
            dest_port INT,
            protocol TEXT,
            rule_id TEXT,
            rule_name TEXT,
            direction TEXT,
            action TEXT,
            result TEXT,
            hit_count INT DEFAULT 1,
            UNIQUE(src_ip, dest_ip, dest_port, protocol, rule_id)
        );
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute(sql)
        except Exception as e:
            logger.error(f"Failed to ensure PostgreSQL table: {e}")

    def write_log(
        self,
        log: ParsedLog,
        src_groups: Optional[List[str]] = None,
        dest_groups: Optional[List[str]] = None,
    ) -> bool:
        """Insert a single flow row."""
        if not self.config.enabled:
            return True
        if not self.conn:
            self._connect()
            if not self.conn:
                return False

        src_group = src_groups[0] if src_groups else None
        dest_group = dest_groups[0] if dest_groups else None

        sql = f"""
        INSERT INTO {self.config.table} (
            src_ip, src_group, dest_ip, dest_group,
            dest_port, protocol, rule_id, rule_name,
            direction, action, result, hit_count
        ) VALUES %s
        ON CONFLICT (src_ip, dest_ip, dest_port, protocol, rule_id)
        DO UPDATE SET
            hit_count = {self.config.table}.hit_count + 1,
            ts = NOW(),
            src_group = EXCLUDED.src_group,
            dest_group = EXCLUDED.dest_group,
            rule_name = EXCLUDED.rule_name,
            direction = EXCLUDED.direction,
            action = EXCLUDED.action,
            result = EXCLUDED.result
        """
        values = [
            (
                log.source_ip,
                src_group,
                log.dest_ip,
                dest_group,
                int(log.dest_port),
                log.protocol,
                log.rule_id,
                log.rule_name,
                log.direction,
                log.action,
                log.result,
                1,  # Initial hit_count
            )
        ]

        try:
            with self.conn.cursor() as cur:
                execute_values(cur, sql, values)
            return True
        except Exception as e:
            logger.debug(f"Failed to insert/update flow in PostgreSQL: {e}")
            return False


