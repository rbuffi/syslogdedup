"""Regression tests for source/dest group filtering in PostgreSQL queries."""
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

sys.modules.setdefault("psycopg2", MagicMock())
sys.modules.setdefault("psycopg2.extras", MagicMock())
from postgres_client import NO_GROUP_VALUE, PostgresClient


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

    def cursor(self, *args, **kwargs):
        return self._cursor


class TestPostgresGroupFilters(unittest.TestCase):
    def _client_with_fake_conn(self):
        cfg = SimpleNamespace(
            enabled=False,
            host="localhost",
            port=5432,
            database="db",
            user="u",
            password="p",
            table="flows",
        )
        client = PostgresClient(cfg)
        fake_cursor = _FakeCursor()
        client.conn = _FakeConn(fake_cursor)
        client._ensure_conn = lambda: True
        return client, fake_cursor

    def test_get_rules_filters_on_group_arrays(self):
        client, cur = self._client_with_fake_conn()

        client.get_rules(source_group="web-tier", dest_group="db-tier")

        self.assertEqual(len(cur.executed), 1)
        sql, params = cur.executed[0]
        self.assertIn("ANY(", sql)
        self.assertIn("NULLIF(src_groups, ARRAY[]::TEXT[])", sql)
        self.assertIn("NULLIF(dest_groups, ARRAY[]::TEXT[])", sql)

        # Source and destination filter values should be passed for ANY checks.
        self.assertEqual(params[4], "web-tier")
        self.assertEqual(params[5], "web-tier")
        self.assertEqual(params[6], NO_GROUP_VALUE)
        self.assertEqual(params[7], "db-tier")
        self.assertEqual(params[8], "db-tier")
        self.assertEqual(params[9], NO_GROUP_VALUE)

    def test_get_rules_grouped_filters_on_group_arrays(self):
        client, cur = self._client_with_fake_conn()

        client.get_rules_grouped(source_group="app", dest_group="shared")

        self.assertEqual(len(cur.executed), 1)
        sql, params = cur.executed[0]
        self.assertIn("ANY(", sql)
        self.assertIn("NULLIF(src_groups, ARRAY[]::TEXT[])", sql)
        self.assertIn("NULLIF(dest_groups, ARRAY[]::TEXT[])", sql)

        # Keep parameter order aligned with SQL placeholders.
        self.assertEqual(params[2], "app")
        self.assertEqual(params[3], "app")
        self.assertEqual(params[4], NO_GROUP_VALUE)
        self.assertEqual(params[5], "shared")
        self.assertEqual(params[6], "shared")
        self.assertEqual(params[7], NO_GROUP_VALUE)

    def test_get_groups_unscoped_uses_window_and_limit(self):
        client, cur = self._client_with_fake_conn()

        client.get_groups(default_window_hours=168, default_limit=1000)

        self.assertEqual(len(cur.executed), 2)
        source_sql, source_params = cur.executed[0]
        dest_sql, dest_params = cur.executed[1]

        self.assertIn("ts >= NOW() - make_interval(hours => %s)", source_sql)
        self.assertIn("LIMIT %s", source_sql)
        self.assertEqual(source_params, (168, NO_GROUP_VALUE, 168, 1000))

        self.assertIn("ts >= NOW() - make_interval(hours => %s)", dest_sql)
        self.assertIn("LIMIT %s", dest_sql)
        self.assertEqual(dest_params, (168, NO_GROUP_VALUE, 168, 1000))

    def test_get_groups_scoped_by_ip_skips_windowed_default(self):
        client, cur = self._client_with_fake_conn()

        client.get_groups(src_ip="10.1.1.1", dest_ip="10.2.2.2")

        self.assertEqual(len(cur.executed), 2)
        source_sql, source_params = cur.executed[0]
        dest_sql, dest_params = cur.executed[1]

        self.assertNotIn("make_interval(hours => %s)", source_sql)
        self.assertNotIn("LIMIT %s", source_sql)
        self.assertEqual(source_params, ("10.1.1.1", NO_GROUP_VALUE, "10.1.1.1"))

        self.assertNotIn("make_interval(hours => %s)", dest_sql)
        self.assertNotIn("LIMIT %s", dest_sql)
        self.assertEqual(dest_params, ("10.2.2.2", NO_GROUP_VALUE, "10.2.2.2"))


if __name__ == "__main__":
    unittest.main()
