"""PostgreSQL client for storing aggregated firewall flows."""
import logging
from typing import Optional, List, Dict, Any

import psycopg2
from psycopg2.extras import execute_values, RealDictCursor

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
            UNIQUE(src_ip, dest_ip, dest_port, protocol)
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
        ON CONFLICT (src_ip, dest_ip, dest_port, protocol)
        DO UPDATE SET
            hit_count = {self.config.table}.hit_count + 1,
            ts = NOW(),
            src_group = EXCLUDED.src_group,
            dest_group = EXCLUDED.dest_group,
            rule_id = EXCLUDED.rule_id,
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

    def _ensure_conn(self) -> bool:
        """Ensure we have a connection (for read-only use when enabled later)."""
        if not self.config.enabled:
            return False
        if not self.conn:
            self._connect()
        return self.conn is not None

    def get_groups(self) -> Dict[str, List[str]]:
        """Return distinct source_group and dest_group lists for dropdowns."""
        out: Dict[str, List[str]] = {"source_groups": [], "dest_groups": []}
        if not self._ensure_conn():
            return out
        t = self.config.table
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    f"""
                    SELECT DISTINCT COALESCE(src_group, '') AS g
                    FROM {t}
                    WHERE src_group IS NOT NULL AND src_group != ''
                    ORDER BY 1
                    """
                )
                out["source_groups"] = [r["g"] for r in cur.fetchall()]
                cur.execute(
                    f"""
                    SELECT DISTINCT COALESCE(dest_group, '') AS g
                    FROM {t}
                    WHERE dest_group IS NOT NULL AND dest_group != ''
                    ORDER BY 1
                    """
                )
                out["dest_groups"] = [r["g"] for r in cur.fetchall()]
        except Exception as e:
            logger.debug(f"Failed to get groups from PostgreSQL: {e}")
        return out

    def get_rules(
        self,
        source_group: Optional[str] = None,
        dest_group: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return flat list of rules with optional filter by source_group, dest_group."""
        if not self._ensure_conn():
            return []
        t = self.config.table
        source_group = (source_group or "").strip()
        dest_group = (dest_group or "").strip()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    f"""
                    SELECT
                        COALESCE(src_group, '')   AS source_group,
                        COALESCE(dest_group, '')  AS dest_group,
                        dest_port,
                        src_ip,
                        dest_ip,
                        direction,
                        result,
                        hit_count,
                        protocol,
                        rule_id,
                        rule_name
                    FROM {t}
                    WHERE (%s = '' OR COALESCE(src_group, '') = %s)
                      AND (%s = '' OR COALESCE(dest_group, '') = %s)
                    ORDER BY src_group, dest_group, hit_count DESC, dest_port
                    """,
                    (source_group, source_group, dest_group, dest_group),
                )
                rows = cur.fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.debug(f"Failed to get rules from PostgreSQL: {e}")
            return []

    def get_rules_grouped(
        self,
        source_group: Optional[str] = None,
        dest_group: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return rules grouped by (source_group, dest_group) with aggregated dest_ports."""
        if not self._ensure_conn():
            return []
        t = self.config.table
        source_group = (source_group or "").strip()
        dest_group = (dest_group or "").strip()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    f"""
                    SELECT
                        COALESCE(src_group, '')   AS source_group,
                        COALESCE(dest_group, '')  AS dest_group,
                        array_agg(DISTINCT dest_port ORDER BY dest_port)
                            FILTER (WHERE dest_port IS NOT NULL) AS dest_ports,
                        direction,
                        result,
                        SUM(hit_count)::BIGINT AS hit_count
                    FROM {t}
                    WHERE (%s = '' OR COALESCE(src_group, '') = %s)
                      AND (%s = '' OR COALESCE(dest_group, '') = %s)
                    GROUP BY src_group, dest_group, direction, result
                    ORDER BY source_group, dest_group, hit_count DESC
                    """,
                    (source_group, source_group, dest_group, dest_group),
                )
                rows = cur.fetchall()
                out = []
                for r in rows:
                    d = dict(r)
                    if d.get("dest_ports") is None:
                        d["dest_ports"] = []
                    elif hasattr(d["dest_ports"], "tolist"):
                        d["dest_ports"] = d["dest_ports"].tolist()
                    out.append(d)
                return out
        except Exception as e:
            logger.debug(f"Failed to get grouped rules from PostgreSQL: {e}")
            return []


