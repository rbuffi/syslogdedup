import unittest

from nsxt_client import NSXTClient
from config import NSXTConfig


class DummyNSXTClient(NSXTClient):
    """
    Minimal subclass that lets us inject a pre-populated groups cache so we can
    exercise applied-to → scope payload construction logic
    without talking to a real NSX-T Manager.
    """

    def __init__(self):
        cfg = NSXTConfig(host="dummy", username="u", password="p", verify_ssl=False)
        super().__init__(cfg)
        # Fake a couple of groups with predictable names and paths
        self._groups = [
            {"id": "g-src", "display_name": "src-group", "path": "/infra/domains/default/groups/src-group"},
            {"id": "g-dst", "display_name": "dst-group", "path": "/infra/domains/default/groups/dst-group"},
        ]

    def _refresh_groups_if_needed(self):
        # Override to avoid real HTTP calls in tests
        return

    def _request_payload_only(
        self,
        *,
        policy_id: str,
        rule_name: str,
        direction: str,
        source_group_names,
        dest_group_names,
        applied_to_group_names,
        service_id: str,
    ):
        # Call the real helper methods but short-circuit before doing HTTP
        src_paths = [self._group_name_to_path(n) for n in source_group_names if n]
        dst_paths = [self._group_name_to_path(n) for n in dest_group_names if n]
        applied_paths = [self._group_name_to_path(n) for n in applied_to_group_names if n]
        service_path = f"/infra/services/{service_id}"
        rule_id = self._sanitize_id(rule_name)
        payload = {
            "id": rule_id,
            "display_name": rule_name,
            "disabled": True,
            "logged": True,
            "source_groups": src_paths,
            "destination_groups": dst_paths,
            "services": [service_path],
            "direction": direction,
            "scope": applied_paths,
            "action": "ALLOW",
        }
        return payload


class TestDirectionAppliedToMapping(unittest.TestCase):
    def setUp(self) -> None:
        self.client = DummyNSXTClient()

    def test_in_direction_applied_to_dest(self):
        payload = self.client._request_payload_only(
            policy_id="pol1",
            rule_name="src-group_dst-group_svc_in",
            direction="IN",
            source_group_names=["src-group"],
            dest_group_names=["dst-group"],
            applied_to_group_names=["dst-group"],
            service_id="svc-1",
        )
        self.assertEqual(
            payload["scope"],
            ["/infra/domains/default/groups/dst-group"],
        )

    def test_out_direction_applied_to_source(self):
        payload = self.client._request_payload_only(
            policy_id="pol1",
            rule_name="src-group_dst-group_svc_out",
            direction="OUT",
            source_group_names=["src-group"],
            dest_group_names=["dst-group"],
            applied_to_group_names=["src-group"],
            service_id="svc-1",
        )
        self.assertEqual(
            payload["scope"],
            ["/infra/domains/default/groups/src-group"],
        )

    def test_in_out_direction_applied_to_both(self):
        payload = self.client._request_payload_only(
            policy_id="pol1",
            rule_name="src-group_dst-group_svc_in-out",
            direction="IN_OUT",
            source_group_names=["src-group"],
            dest_group_names=["dst-group"],
            applied_to_group_names=["src-group", "dst-group"],
            service_id="svc-1",
        )
        self.assertEqual(
            sorted(payload["scope"]),
            sorted(
                [
                    "/infra/domains/default/groups/src-group",
                    "/infra/domains/default/groups/dst-group",
                ]
            ),
        )


if __name__ == "__main__":
    unittest.main()

