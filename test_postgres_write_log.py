"""Tests for PostgreSQL write_log reconnect behavior."""
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.modules.setdefault("psycopg2", MagicMock())
sys.modules.setdefault("psycopg2.extras", MagicMock())

from parser import ParsedLog
from postgres_client import PostgresClient


def _sample_log() -> ParsedLog:
    return ParsedLog(
        timestamp_id="1",
        network_type="INET",
        action="match",
        result="PASS",
        rule_id="100",
        direction="OUT",
        size_id="73",
        protocol="UDP",
        source_ip="10.1.1.1",
        source_port="12345",
        dest_ip="10.2.2.2",
        dest_port="53",
        rule_name="test-rule",
        original_line="",
    )


class TestPostgresWriteLog(unittest.TestCase):
    def _client(self) -> PostgresClient:
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
        client.conn = MagicMock()
        return client

    def test_write_log_uses_ensure_conn(self):
        client = self._client()
        with patch.object(client, "_ensure_conn", return_value=True) as ensure:
            with patch("postgres_client.execute_values") as execute_values:
                ok = client.write_log(_sample_log())

        ensure.assert_called()
        execute_values.assert_called_once()
        self.assertTrue(ok)

    def test_write_log_retries_once_after_failure(self):
        client = self._client()
        calls = {"n": 0}

        def fake_execute(*_args, **_kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("server closed the connection unexpectedly")

        def ensure_conn():
            if client.conn is None:
                client.conn = MagicMock()
            return True

        with patch.object(client, "_ensure_conn", side_effect=ensure_conn):
            with patch("postgres_client.execute_values", side_effect=fake_execute):
                ok = client.write_log(_sample_log())

        self.assertTrue(ok)
        self.assertEqual(calls["n"], 2)


if __name__ == "__main__":
    unittest.main()
