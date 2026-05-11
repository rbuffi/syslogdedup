"""Tests for NSX group list refresh (member_types fallback, parallel scan helpers)."""
import unittest
from unittest.mock import MagicMock, patch

import requests

from config import NSXTConfig
from nsxt_client import NSXTClient


class TestReloadCatalogMemberTypesFallback(unittest.TestCase):
    def test_fallback_unfiltered_on_400(self):
        cfg = NSXTConfig(
            host="mgr.example",
            username="u",
            password="p",
            verify_ssl=False,
            group_list_member_types=None,
        )
        client = NSXTClient(cfg)
        state = {"n": 0}

        def fake_nsx_get(self, url, params=None, *, timeout=30):
            state["n"] += 1
            r = MagicMock()
            if params and params.get("member_types"):
                r.raise_for_status.side_effect = requests.exceptions.HTTPError(
                    response=MagicMock(status_code=400)
                )
            else:

                def ok():
                    pass

                r.raise_for_status = ok
                r.json.return_value = {
                    "results": [
                        {
                            "id": "g1",
                            "path": "/infra/domains/default/groups/g1",
                            "display_name": "G1",
                            "expression": [
                                {
                                    "resource_type": "IPAddressExpression",
                                    "ip_addresses": ["10.0.0.1"],
                                }
                            ],
                        }
                    ],
                    "cursor": None,
                }
            return r

        with patch.object(NSXTClient, "_nsx_get", fake_nsx_get):
            client._reload_catalog_from_group_list_only()

        self.assertEqual(state["n"], 2)
        self.assertEqual(len(client._groups), 1)
        self.assertEqual(client._groups[0]["id"], "g1")

    def test_off_skips_member_types_param(self):
        cfg = NSXTConfig(
            host="mgr.example",
            username="u",
            password="p",
            verify_ssl=False,
            group_list_member_types="off",
        )
        client = NSXTClient(cfg)
        seen_params = []

        def fake_nsx_get(self, url, params=None, *, timeout=30):
            seen_params.append(dict(params or {}))
            r = MagicMock()

            def ok():
                pass

            r.raise_for_status = ok
            r.json.return_value = {"results": [], "cursor": None}
            return r

        with patch.object(NSXTClient, "_nsx_get", fake_nsx_get):
            client._reload_catalog_from_group_list_only()

        self.assertTrue(seen_params)
        self.assertNotIn("member_types", seen_params[0])


class TestParallelGroupMatching(unittest.TestCase):
    def test_collect_parallel_empty(self):
        cfg = NSXTConfig(
            host="h",
            username="u",
            password="p",
            verify_ssl=False,
            ip_group_lookup_parallelism=4,
        )
        client = NSXTClient(cfg)
        client._groups = [{"id": f"g{i}", "path": f"/infra/domains/default/groups/g{i}", "expression": []} for i in range(80)]
        client._rebuild_group_maps()
        with patch.object(NSXTClient, "_ip_matches_group", return_value=False):
            r = client._collect_groups_matching_ip("10.0.0.2")
        self.assertEqual(r, [])

    def test_split_chunks(self):
        cfg = NSXTConfig(host="h", username="u", password="p", verify_ssl=False)
        client = NSXTClient(cfg)
        seq = [{"id": str(i)} for i in range(10)]
        chunks = client._split_catalog_into_chunks(seq, 3)
        self.assertEqual(sum(len(c) for c in chunks), 10)
        self.assertEqual(len(chunks), 3)


class TestMacOnlyGroupSkipsMembers(unittest.TestCase):
    def test_mac_only_returns_false_without_scan(self):
        cfg = NSXTConfig(host="h", username="u", password="p", verify_ssl=False)
        client = NSXTClient(cfg)
        g = {
            "id": "macg",
            "path": "/infra/domains/default/groups/macg",
            "expression": [{"resource_type": "MACAddressExpression", "mac_addresses": ["aa:bb:cc:dd:ee:ff"]}],
        }
        with patch.object(NSXTClient, "_group_ip_matches_members_paginated_scan") as scan:
            self.assertFalse(client._ip_matches_group("10.0.0.1", g))
            scan.assert_not_called()


class TestLookupOnlyNamedGroups(unittest.TestCase):
    def test_named_only_skips_catalog_reload(self):
        cfg = NSXTConfig(host="h", username="u", password="p", verify_ssl=False)
        client = NSXTClient(cfg)
        detail = {
            "id": "g1",
            "display_name": "MyG",
            "path": "/infra/domains/default/groups/g1",
            "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.1.1.1"]}],
        }

        with patch.object(NSXTClient, "_reload_catalog_from_group_list_only") as rel:
            with patch.object(NSXTClient, "_resolve_group_detail_for_lookup_name", return_value=detail):
                out = client.lookup_all_ip_groups("10.1.1.1", refresh=False, only_group_names=["MyG"])
        rel.assert_not_called()
        self.assertEqual(out, ["MyG"])

    def test_named_only_returns_empty_when_no_match(self):
        cfg = NSXTConfig(host="h", username="u", password="p", verify_ssl=False)
        client = NSXTClient(cfg)
        detail = {
            "id": "g1",
            "display_name": "MyG",
            "path": "/infra/domains/default/groups/g1",
            "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.1.1.1"]}],
        }
        with patch.object(NSXTClient, "_reload_catalog_from_group_list_only") as rel:
            with patch.object(NSXTClient, "_resolve_group_detail_for_lookup_name", return_value=detail):
                with patch.object(NSXTClient, "_group_ip_matches_members_paginated_scan", return_value=False):
                    out = client.lookup_all_ip_groups("10.9.9.9", refresh=False, only_group_names=["MyG"])
        rel.assert_not_called()
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
