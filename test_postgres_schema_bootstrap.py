"""Tests for PostgreSQL schema bootstrap and web startup index ensure."""
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.modules.setdefault("psycopg2", MagicMock())
sys.modules.setdefault("psycopg2.extras", MagicMock())

from postgres_client import PostgresClient


class _FakeCursor:
    def __init__(self):
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchall(self):
        return []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor
        self.closed = 0

    def cursor(self, *args, **kwargs):
        return self._cursor


class TestEnsureSchema(unittest.TestCase):
    def test_returns_false_when_postgres_disabled(self):
        cfg = SimpleNamespace(
            enabled=False,
            host="localhost",
            port=5432,
            database="db",
            user="u",
            password="p",
            table="flows",
        )
        with patch.object(PostgresClient, "_connect"):
            with patch.object(PostgresClient, "_ensure_table"):
                client = PostgresClient(cfg)
        self.assertFalse(client.ensure_schema())

    def test_runs_index_ddl_on_fake_connection(self):
        cfg = SimpleNamespace(
            enabled=True,
            host="localhost",
            port=5432,
            database="db",
            user="u",
            password="p",
            table="flows",
        )
        with patch.object(PostgresClient, "_connect"):
            with patch.object(PostgresClient, "_ensure_table"):
                client = PostgresClient(cfg)
        fake_cursor = _FakeCursor()
        client.conn = _FakeConn(fake_cursor)
        client._schema_ready = False

        self.assertTrue(client.ensure_schema())
        index_sql = [sql for sql, _ in fake_cursor.executed if "CREATE INDEX IF NOT EXISTS" in sql]
        self.assertTrue(any("flows_ts_desc_idx" in sql for sql in index_sql))
        self.assertTrue(any("flows_src_group_norm_idx" in sql for sql in index_sql))
        self.assertTrue(client._schema_ready)

    def test_schema_ready_skips_second_ensure_table(self):
        cfg = SimpleNamespace(
            enabled=True,
            host="localhost",
            port=5432,
            database="db",
            user="u",
            password="p",
            table="flows",
        )
        with patch.object(PostgresClient, "_connect"):
            with patch.object(PostgresClient, "_ensure_table", return_value=True):
                client = PostgresClient(cfg)
        client._schema_ready = True
        with patch.object(client, "_ensure_table", return_value=True) as ensure_table:
            self.assertTrue(client.ensure_schema())
            ensure_table.assert_not_called()


def _import_web_module():
    import os

    os.environ.setdefault("WEB_ONLY", "true")
    os.environ.setdefault("PG_ENABLED", "true")
    os.environ.setdefault("PG_DB", "firewall")
    os.environ.setdefault("PG_USER", "firewall")
    import web

    return web


class TestBootstrapPostgresSchema(unittest.TestCase):
    def test_skips_when_postgres_disabled(self):
        web = _import_web_module()

        with patch.object(web.config.postgres, "enabled", False):
            with patch.object(web.pg, "ensure_schema") as ensure_schema:
                web.bootstrap_postgres_schema()
        ensure_schema.assert_not_called()

    def test_retries_until_success(self):
        web = _import_web_module()

        with patch.object(web.config.postgres, "enabled", True):
            with patch.object(web.pg, "ensure_schema", side_effect=[False, False, True]) as ensure_schema:
                with patch.object(web.time, "sleep") as sleep:
                    with patch.object(web.time, "monotonic", side_effect=[0.0, 1.0, 2.0, 3.0]):
                        web.bootstrap_postgres_schema()
        self.assertEqual(ensure_schema.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_raises_after_timeout(self):
        web = _import_web_module()

        with patch.object(web.config.postgres, "enabled", True):
            with patch.object(web.pg, "ensure_schema", return_value=False):
                with patch.object(web.time, "sleep"):
                    with patch.object(web.time, "monotonic", side_effect=[0.0, 30.0, 61.0]):
                        with self.assertRaises(RuntimeError):
                            web.bootstrap_postgres_schema()


if __name__ == "__main__":
    unittest.main()
