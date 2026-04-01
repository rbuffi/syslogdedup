"""PostgreSQL client for storing aggregated firewall flows."""
import logging
from typing import Optional, List, Dict, Any

import psycopg2
from psycopg2.extras import execute_values, RealDictCursor

from config import PostgresConfig
from parser import ParsedLog


logger = logging.getLogger(__name__)
NO_GROUP_VALUE = "nogroup"


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
            src_groups TEXT[],
            dest_ip TEXT NOT NULL,
            dest_group TEXT,
            dest_groups TEXT[],
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
                # Backward-compatible schema evolution for existing deployments.
                cur.execute(f"ALTER TABLE {self.config.table} ADD COLUMN IF NOT EXISTS src_groups TEXT[]")
                cur.execute(f"ALTER TABLE {self.config.table} ADD COLUMN IF NOT EXISTS dest_groups TEXT[]")
                # Backfill arrays for historical rows so UI dropdown filtering
                # has non-empty values even before those rows are re-ingested.
                cur.execute(
                    f"""
                    UPDATE {self.config.table}
                    SET
                        src_groups = ARRAY[COALESCE(NULLIF(src_group, ''), %s)]
                    WHERE src_groups IS NULL
                       OR array_length(src_groups, 1) IS NULL
                       OR array_length(src_groups, 1) = 0
                    """,
                    (NO_GROUP_VALUE,),
                )
                cur.execute(
                    f"""
                    UPDATE {self.config.table}
                    SET
                        dest_groups = ARRAY[COALESCE(NULLIF(dest_group, ''), %s)]
                    WHERE dest_groups IS NULL
                       OR array_length(dest_groups, 1) IS NULL
                       OR array_length(dest_groups, 1) = 0
                    """,
                    (NO_GROUP_VALUE,),
                )
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

        src_group = src_groups[0] if src_groups else NO_GROUP_VALUE
        dest_group = dest_groups[0] if dest_groups else NO_GROUP_VALUE
        src_groups_list = [g for g in (src_groups or []) if g]
        dest_groups_list = [g for g in (dest_groups or []) if g]
        if not src_groups_list:
            src_groups_list = [NO_GROUP_VALUE]
        if not dest_groups_list:
            dest_groups_list = [NO_GROUP_VALUE]

        sql = f"""
        INSERT INTO {self.config.table} (
            src_ip, src_group, src_groups, dest_ip, dest_group, dest_groups,
            dest_port, protocol, rule_id, rule_name,
            direction, action, result, hit_count
        ) VALUES %s
        ON CONFLICT (src_ip, dest_ip, dest_port, protocol)
        DO UPDATE SET
            hit_count = {self.config.table}.hit_count + 1,
            ts = NOW(),
            src_group = EXCLUDED.src_group,
            src_groups = EXCLUDED.src_groups,
            dest_group = EXCLUDED.dest_group,
            dest_groups = EXCLUDED.dest_groups,
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
                src_groups_list if src_groups_list else None,
                log.dest_ip,
                dest_group,
                dest_groups_list if dest_groups_list else None,
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
        """Ensure we have a live connection suitable for read APIs."""
        if not self.config.enabled:
            return False

        # Establish initial connection if needed
        if self.conn is None:
            self._connect()

        # Reconnect if connection object exists but is closed
        if self.conn is not None and getattr(self.conn, "closed", 0):
            logger.info("PostgreSQL connection was closed; reconnecting")
            self._connect()

        # Lightweight health check; if it fails, reconnect once
        if self.conn is not None:
            try:
                with self.conn.cursor() as cur:
                    cur.execute("SELECT 1")
            except Exception:
                logger.info("PostgreSQL connection unhealthy; reconnecting")
                self._connect()

        return self.conn is not None

    def get_groups(
        self,
        src_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
    ) -> Dict[str, List[str]]:
        """Return distinct source_group and dest_group lists for dropdowns."""
        out: Dict[str, List[str]] = {"source_groups": [], "dest_groups": []}
        if not self._ensure_conn():
            return out
        t = self.config.table
        src_ip = (src_ip or "").strip()
        dest_ip = (dest_ip or "").strip()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Source groups: scoped by src_ip when set; otherwise all distinct
                # source groups in the table (for main-screen dropdowns on load).
                if src_ip:
                    cur.execute(
                        f"""
                        SELECT DISTINCT g
                        FROM (
                            SELECT unnest(COALESCE(src_groups, ARRAY[]::TEXT[])) AS g
                            FROM {t}
                            WHERE src_ip = %s
                            UNION
                            SELECT COALESCE(NULLIF(src_group, ''), %s) AS g
                            FROM {t}
                            WHERE src_ip = %s
                        ) src
                        WHERE g IS NOT NULL AND g != ''
                        ORDER BY 1
                        """,
                        (src_ip, NO_GROUP_VALUE, src_ip),
                    )
                else:
                    cur.execute(
                        f"""
                        SELECT DISTINCT g
                        FROM (
                            SELECT unnest(COALESCE(src_groups, ARRAY[]::TEXT[])) AS g
                            FROM {t}
                            UNION
                            SELECT COALESCE(NULLIF(src_group, ''), %s) AS g
                            FROM {t}
                        ) src
                        WHERE g IS NOT NULL AND g != ''
                        ORDER BY 1
                        """,
                        (NO_GROUP_VALUE,),
                    )
                out["source_groups"] = [r["g"] for r in cur.fetchall()]

                # Dest groups: scoped by dest_ip when set; otherwise all distinct.
                if dest_ip:
                    cur.execute(
                        f"""
                        SELECT DISTINCT g
                        FROM (
                            SELECT unnest(COALESCE(dest_groups, ARRAY[]::TEXT[])) AS g
                            FROM {t}
                            WHERE dest_ip = %s
                            UNION
                            SELECT COALESCE(NULLIF(dest_group, ''), %s) AS g
                            FROM {t}
                            WHERE dest_ip = %s
                        ) dst
                        WHERE g IS NOT NULL AND g != ''
                        ORDER BY 1
                        """,
                        (dest_ip, NO_GROUP_VALUE, dest_ip),
                    )
                else:
                    cur.execute(
                        f"""
                        SELECT DISTINCT g
                        FROM (
                            SELECT unnest(COALESCE(dest_groups, ARRAY[]::TEXT[])) AS g
                            FROM {t}
                            UNION
                            SELECT COALESCE(NULLIF(dest_group, ''), %s) AS g
                            FROM {t}
                        ) dst
                        WHERE g IS NOT NULL AND g != ''
                        ORDER BY 1
                        """,
                        (NO_GROUP_VALUE,),
                    )
                out["dest_groups"] = [r["g"] for r in cur.fetchall()]
        except Exception as e:
            logger.debug(f"Failed to get groups from PostgreSQL: {e}")
        return out

    def get_rules(
        self,
        source_group: Optional[str] = None,
        dest_group: Optional[str] = None,
        hours: Optional[int] = None,
        src_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        dest_port: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return flat list of rules with optional filter by source_group, dest_group."""
        if not self._ensure_conn():
            return []
        t = self.config.table
        source_group = (source_group or "").strip()
        dest_group = (dest_group or "").strip()
        hours = int(hours or 0)
        src_ip = (src_ip or "").strip()
        dest_ip = (dest_ip or "").strip()
        dest_port = (dest_port or "").strip()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    f"""
                    SELECT
                        COALESCE(NULLIF(src_group, ''), %s)   AS source_group,
                        COALESCE(NULLIF(dest_group, ''), %s)  AS dest_group,
                        COALESCE(
                            NULLIF(src_groups, ARRAY[]::TEXT[]),
                            ARRAY[COALESCE(NULLIF(src_group, ''), %s)]
                        ) AS source_groups,
                        COALESCE(
                            NULLIF(dest_groups, ARRAY[]::TEXT[]),
                            ARRAY[COALESCE(NULLIF(dest_group, ''), %s)]
                        ) AS dest_groups,
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
                    WHERE (%s = '' OR COALESCE(NULLIF(src_group, ''), %s) = %s)
                      AND (%s = '' OR COALESCE(NULLIF(dest_group, ''), %s) = %s)
                      AND (%s = 0 OR ts >= NOW() - make_interval(hours => %s))
                      AND (%s = '' OR src_ip ILIKE '%%' || %s || '%%')
                      AND (%s = '' OR dest_ip ILIKE '%%' || %s || '%%')
                      AND (%s = '' OR CAST(dest_port AS TEXT) = %s)
                    ORDER BY hit_count DESC, dest_port
                    LIMIT 500
                    """,
                    (
                        NO_GROUP_VALUE,
                        NO_GROUP_VALUE,
                        NO_GROUP_VALUE,
                        NO_GROUP_VALUE,
                        source_group,
                        NO_GROUP_VALUE,
                        source_group,
                        dest_group,
                        NO_GROUP_VALUE,
                        dest_group,
                        hours,
                        hours,
                        src_ip,
                        src_ip,
                        dest_ip,
                        dest_ip,
                        dest_port,
                        dest_port,
                    ),
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
        hours: Optional[int] = None,
        src_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        dest_port: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return rules grouped by (source_group, dest_group) with aggregated dest_ports."""
        if not self._ensure_conn():
            return []
        t = self.config.table
        source_group = (source_group or "").strip()
        dest_group = (dest_group or "").strip()
        hours = int(hours or 0)
        src_ip = (src_ip or "").strip()
        dest_ip = (dest_ip or "").strip()
        dest_port = (dest_port or "").strip()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    f"""
                    SELECT
                        COALESCE(NULLIF(src_group, ''), %s)   AS source_group,
                        COALESCE(NULLIF(dest_group, ''), %s)  AS dest_group,
                        array_agg(DISTINCT dest_port ORDER BY dest_port)
                            FILTER (WHERE dest_port IS NOT NULL) AS dest_ports,
                        direction,
                        result,
                        SUM(hit_count)::BIGINT AS hit_count
                    FROM {t}
                    WHERE (%s = '' OR COALESCE(NULLIF(src_group, ''), %s) = %s)
                      AND (%s = '' OR COALESCE(NULLIF(dest_group, ''), %s) = %s)
                      AND (%s = 0 OR ts >= NOW() - make_interval(hours => %s))
                      AND (%s = '' OR src_ip ILIKE '%%' || %s || '%%')
                      AND (%s = '' OR dest_ip ILIKE '%%' || %s || '%%')
                      AND (%s = '' OR CAST(dest_port AS TEXT) = %s)
                    GROUP BY src_group, dest_group, direction, result
                    ORDER BY hit_count DESC, source_group, dest_group
                    LIMIT 200
                    """,
                    (
                        NO_GROUP_VALUE,
                        NO_GROUP_VALUE,
                        source_group,
                        NO_GROUP_VALUE,
                        source_group,
                        dest_group,
                        NO_GROUP_VALUE,
                        dest_group,
                        hours,
                        hours,
                        src_ip,
                        src_ip,
                        dest_ip,
                        dest_ip,
                        dest_port,
                        dest_port,
                    ),
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


