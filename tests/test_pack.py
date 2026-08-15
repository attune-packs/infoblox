from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

try:
    import requests  # noqa: F401
except ImportError:
    requests_stub = types.ModuleType("requests")
    requests_stub.RequestException = type("RequestException", (Exception,), {})
    requests_stub.Session = lambda: None
    sys.modules["requests"] = requests_stub

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import infoblox_client as client


EXPECTED_ACTIONS = {
    "address_search", "dns_view_delete", "dns_view_list", "dns_view_upsert",
    "fixed_address_allocate", "fixed_address_delete", "fixed_address_list",
    "fixed_address_upsert", "network_delete", "network_list",
    "network_upsert", "network_view_delete", "network_view_list",
    "network_view_upsert", "next_available_ip", "record_delete", "record_list",
    "record_upsert", "zone_delete", "zone_list", "zone_upsert",
}


class Response:
    def __init__(self, value=None, status=200, content=b"json"):
        self.value = value
        self.status_code = status
        self.content = content

    def json(self):
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class Session:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError("unexpected HTTP request")
        return self.responses.pop(0)


def config(**overrides):
    return {
        "base_url": "https://grid.example.invalid/proxy",
        "username": "api-user",
        "password": "synthetic-secret",
        **overrides,
    }


def api(*responses, **overrides):
    session = Session(*responses)
    return client.InfobloxClient(config(**overrides), session=session), session


def page(items, next_page_id=None):
    value = {"result": items}
    if next_page_id is not None:
        value["next_page_id"] = next_page_id
    return Response(value)


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            path.stem: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "actions").glob("*.yaml"))
        }

    def test_expected_flat_key_backed_actions(self):
        self.assertEqual(EXPECTED_ACTIONS, set(self.actions))
        for name, text in self.actions.items():
            with self.subTest(name=name):
                for required in (
                    f"ref: infoblox.{name}", "runner_type: python",
                    'runtime_version: ">=3.10"', "entry_point: infoblox_action.py",
                    "parameter_delivery: stdin", "parameter_format: json",
                    "output_format: json", "default_execution_permission_set_refs: [standard]",
                    'default: "infoblox.credentials", key_ref: true',
                    "operation: {type: string, required: true}",
                    "result: {type: object, required: true}",
                ):
                    self.assertIn(required, text)
                self.assertNotIn("  username:", text)
                self.assertNotIn("  password:", text)
                self.assertNotIn("  base_url:", text)

    def test_destructive_contracts_require_boolean_and_identity_confirmation(self):
        destructive = {
            "network_view_delete": "confirm_name",
            "network_delete": "confirm_network",
            "fixed_address_delete": "confirm_address",
            "dns_view_delete": "confirm_name",
            "zone_delete": "confirm_fqdn",
            "record_delete": "confirm_value",
        }
        for name, identity in destructive.items():
            text = self.actions[name]
            self.assertIn("confirm: {type: boolean, const: true, required: true", text)
            self.assertIn(f"  {identity}:", text)

    def test_readme_lists_every_action_and_source_is_pinned(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for name in EXPECTED_ACTIONS:
            self.assertIn(f"`infoblox.{name}`", readme)
        source = json.loads((ROOT / "SOURCE.json").read_text(encoding="utf-8"))
        self.assertEqual("1.1.1", source["upstream"]["version"])
        self.assertEqual("49ab61fed17ed05bb72b4c4506890f88aa873569", source["upstream"]["revision"])
        self.assertEqual("Apache-2.0", source["upstream"]["license"])
        self.assertEqual("2.13.7", source["api_reference"]["version"])
        digest = hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
        self.assertEqual("cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30", digest)


class ClientTests(unittest.TestCase):
    def test_configuration_requires_https_tls_and_bounded_timeouts(self):
        valid = client._settings(config(
            wapi_version="2.13.7", ca_bundle="/private/ca.pem",
            connect_timeout_seconds=4, read_timeout_seconds=20,
        ))
        self.assertEqual(valid, ("https://grid.example.invalid/proxy", "api-user", "synthetic-secret", (4.0, 20.0), "/private/ca.pem"))
        invalid = [
            {},
            config(base_url="http://grid.invalid"),
            config(base_url="https://user@grid.invalid"),
            config(base_url="https://grid.invalid/wapi/v2.13.7"),
            config(base_url="https://grid.invalid?q=1"),
            config(base_url="https://grid.invalid:bad"),
            config(verify_tls=False),
            config(ca_bundle="relative.pem"),
            config(wapi_version="2.13.7?x=1"),
            config(connect_timeout_seconds=0),
            config(read_timeout_seconds=301),
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(client.InfobloxPackError):
                client._settings(value)

    def test_request_keeps_query_separate_uses_basic_auth_and_ref_is_safe(self):
        appliance, session = api(Response({"result": []}))
        appliance.request("GET", "/record:a", params={"name": "a+b & c", "_return_fields": "name,ipv4addr"})
        method, url, kwargs = session.calls[0]
        self.assertEqual("GET", method)
        self.assertEqual("https://grid.example.invalid/proxy/wapi/v2.13.7/record:a", url)
        self.assertNotIn("a+b", url)
        self.assertEqual("a+b & c", kwargs["params"]["name"])
        self.assertEqual(("api-user", "synthetic-secret"), kwargs["auth"])
        self.assertTrue(kwargs["verify"])
        self.assertEqual((5.0, 30.0), kwargs["timeout"])
        self.assertFalse(kwargs["allow_redirects"])
        self.assertNotIn("Authorization", kwargs["headers"])
        self.assertEqual("record:a/Ab_9-", appliance.canonical_ref("record:a/Ab_9-:name/with%2Fparts/default", "record:a"))
        for bad in ("record:aaaa/abc:name", "record:a/abc?x=1", "record:a/abc/extra"):
            with self.subTest(bad=bad), self.assertRaises(client.InfobloxPackError):
                appliance.canonical_ref(bad, "record:a")

    def test_paging_is_bounded_and_preserves_encoded_params(self):
        appliance, session = api(
            page([{"_ref": "network/a:10.0.0.0/24/default"}], "safe-page-2"),
            page([{"_ref": "network/b:10.0.1.0/24/default"}], "safe-page-3"),
        )
        result = appliance.search("network", {"network_view": "space & plus+"}, return_fields=["network", "comment"], page_size=1, max_pages=2)
        self.assertEqual(2, result["count"])
        self.assertEqual(2, result["pages_fetched"])
        self.assertTrue(result["truncated"])
        self.assertEqual("safe-page-3", result["next_page_id"])
        self.assertEqual("space & plus+", session.calls[0][2]["params"]["network_view"])
        self.assertEqual("safe-page-2", session.calls[1][2]["params"]["_page_id"])
        self.assertEqual("network,comment", session.calls[0][2]["params"]["_return_fields"])

        repeated, _ = api(page([], "same"), page([], "same"))
        with self.assertRaisesRegex(client.InfobloxPackError, "repeated"):
            repeated.search("network", {}, page_size=1, max_pages=3)

    def test_remote_and_transport_errors_do_not_leak_secrets(self):
        cases = [Response({"Error": "synthetic-secret trace"}, status=500), Response(ValueError("synthetic-secret"))]
        for response in cases:
            with self.subTest(status=response.status_code):
                appliance, _ = api(response)
                with self.assertRaises(client.InfobloxPackError) as raised:
                    appliance.request("GET", "/network")
                self.assertNotIn("synthetic-secret", str(raised.exception))

        class Broken:
            def request(self, *args, **kwargs):
                raise OSError("/secret/certificate/path")

        appliance = client.InfobloxClient(config(), session=Broken())
        with self.assertRaises(client.InfobloxPackError) as raised:
            appliance.request("GET", "/network")
        self.assertNotIn("certificate", str(raised.exception))


class ActionTests(unittest.TestCase):
    def test_network_upsert_is_idempotent_and_updates_by_returned_ref(self):
        current = {"_ref": "network/opaque:10.0.0.0/24/default", "network": "10.0.0.0/24", "network_view": "default", "comment": "same"}
        appliance, session = api(page([current]))
        result = client.execute_with_client("network_upsert", {"network": "10.0.0.7/24", "comment": "same"}, appliance)
        self.assertFalse(result["changed"])
        self.assertEqual(1, len(session.calls))
        self.assertEqual("10.0.0.0/24", session.calls[0][2]["params"]["network"])

        appliance, session = api(page([current]), Response({**current, "comment": "new"}))
        result = client.execute_with_client("network_upsert", {"network": "10.0.0.0/24", "comment": "new"}, appliance)
        self.assertTrue(result["changed"])
        method, url, kwargs = session.calls[1]
        self.assertEqual("PUT", method)
        self.assertTrue(url.endswith("/network/opaque"))
        self.assertEqual({"comment": "new"}, kwargs["json"])

    def test_network_delete_requires_confirmation_and_never_uses_input_ref(self):
        appliance, session = api()
        with self.assertRaises(client.InfobloxPackError):
            client.execute_with_client("network_delete", {"network": "10.0.0.0/24", "confirm": False, "confirm_network": "10.0.0.0/24"}, appliance)
        self.assertEqual([], session.calls)

        found = {"_ref": "network/SAFE_REF:10.0.0.0/24/default", "network": "10.0.0.0/24", "network_view": "default"}
        appliance, session = api(page([found]), Response("network/SAFE_REF:ignored"))
        result = client.execute_with_client("network_delete", {"network": "10.0.0.0/24", "confirm": True, "confirm_network": "10.0.0.0/24"}, appliance)
        self.assertTrue(result["deleted"])
        self.assertEqual("network/SAFE_REF", result["reference"])
        self.assertTrue(session.calls[1][1].endswith("/network/SAFE_REF"))

    def test_default_views_cannot_be_deleted(self):
        for operation, object_type in (("network_view_delete", "networkview"), ("dns_view_delete", "view")):
            appliance, session = api(page([{"_ref": f"{object_type}/x:default/true", "name": "default", "is_default": True}]))
            with self.subTest(operation=operation), self.assertRaisesRegex(client.InfobloxPackError, "default"):
                client.execute_with_client(operation, {"name": "default", "confirm_name": "default", "confirm": True}, appliance)
            self.assertEqual(1, len(session.calls))

    def test_next_available_ip_is_explicitly_non_reserving(self):
        network = {"_ref": "network/netref:10.0.0.0/24/default", "network": "10.0.0.0/24", "network_view": "default"}
        appliance, session = api(page([network]), Response({"ips": ["10.0.0.10", "10.0.0.11"]}))
        result = client.execute_with_client("next_available_ip", {"network": "10.0.0.0/24", "num": 2, "exclude": ["10.0.0.1"]}, appliance)
        self.assertFalse(result["reserved"])
        self.assertIn("does not reserve", result["race_warning"])
        method, url, kwargs = session.calls[1]
        self.assertEqual("POST", method)
        self.assertTrue(url.endswith("/network/netref"))
        self.assertEqual("next_available_ip", kwargs["params"]["_function"])
        self.assertEqual({"num": 2, "exclude": ["10.0.0.1"]}, kwargs["json"])

    def test_fixed_address_allocation_uses_atomic_inline_function(self):
        source = {"_ref": "network/netref:10.0.0.0/24/default", "network": "10.0.0.0/24", "network_view": "default"}
        created = {"_ref": "fixedaddress/fixedref:10.0.0.10/default", "ipv4addr": "10.0.0.10", "mac": "00:11:22:33:44:55"}
        appliance, session = api(page([]), page([source]), Response(created))
        result = client.execute_with_client("fixed_address_allocate", {
            "network": "10.0.0.0/24", "client_identifier": "00-11-22-33-44-55",
            "exclude": ["10.0.0.1"], "comment": "allocated",
        }, appliance)
        self.assertTrue(result["created"])
        self.assertEqual("atomic-inline", result["allocation"])
        method, url, kwargs = session.calls[2]
        self.assertEqual(("POST", "https://grid.example.invalid/proxy/wapi/v2.13.7/fixedaddress"), (method, url))
        inline = kwargs["json"]["ipv4addr"]
        self.assertEqual("next_available_ip", inline["_object_function"])
        self.assertEqual("network/netref", inline["_object_ref"])
        self.assertEqual(["10.0.0.1"], inline["_parameters"]["exclude"])
        self.assertEqual("00:11:22:33:44:55", kwargs["json"]["mac"])

        existing, session = api(page([created]))
        result = client.execute_with_client("fixed_address_allocate", {"network": "10.0.0.0/24", "client_identifier": "00:11:22:33:44:55"}, existing)
        self.assertFalse(result["changed"])
        self.assertEqual(1, len(session.calls))

    def test_record_create_update_delete_and_ptr_identity_are_exact(self):
        appliance, session = api(page([]), Response({"_ref": "record:a/new:www/def", "name": "www.example", "ipv4addr": "192.0.2.1", "view": "default"}))
        result = client.execute_with_client("record_upsert", {"record_type": "A", "name": "www.example", "value": "192.0.2.1", "ttl": 300}, appliance)
        self.assertTrue(result["created"])
        self.assertEqual(True, session.calls[1][2]["json"]["use_ttl"])

        old = {"_ref": "record:a/old:www/def", "name": "www.example", "ipv4addr": "192.0.2.1", "view": "default"}
        updated = {**old, "ipv4addr": "192.0.2.2"}
        appliance, session = api(page([old]), Response(updated))
        result = client.execute_with_client("record_upsert", {"record_type": "A", "name": "www.example", "current_value": "192.0.2.1", "value": "192.0.2.2"}, appliance)
        self.assertTrue(result["changed"])
        self.assertEqual({"ipv4addr": "192.0.2.2"}, session.calls[1][2]["json"])

        other = {"_ref": "record:cname/other:x/def", "name": "alias.example", "canonical": "other.example", "view": "default"}
        appliance, session = api(page([]))
        result = client.execute_with_client("record_delete", {"record_type": "CNAME", "name": "alias.example", "value": "wanted.example", "confirm_value": "wanted.example", "confirm": True}, appliance)
        self.assertFalse(result["deleted"])
        self.assertEqual("wanted.example", session.calls[0][2]["params"]["canonical"])
        self.assertNotEqual(other["canonical"], session.calls[0][2]["params"]["canonical"])

        ptr = {"_ref": "record:ptr/ptrref:1.2.0.192.in-addr.arpa/default", "ipv4addr": "192.0.2.1", "ptrdname": "host.example", "view": "default"}
        appliance, session = api(page([ptr]), Response("record:ptr/ptrref:ignored"))
        result = client.execute_with_client("record_delete", {"record_type": "PTR", "address": "192.0.2.1", "value": "host.example", "confirm_value": "host.example", "confirm": True}, appliance)
        self.assertTrue(result["deleted"])
        self.assertEqual("192.0.2.1", session.calls[0][2]["params"]["ipv4addr"])
        self.assertEqual("host.example", session.calls[0][2]["params"]["ptrdname"])

        appliance, session = api(page([]), Response({"_ref": "record:ptr/new:x/default", "ipv6addr": "2001:db8::1", "ptrdname": "new.example"}))
        result = client.execute_with_client("record_upsert", {"record_type": "PTR", "address": "2001:db8::1", "value": "new.example"}, appliance)
        self.assertTrue(result["created"])
        self.assertEqual("new.example", session.calls[0][2]["params"]["ptrdname"])

    def test_mutable_comments_can_be_cleared_idempotently(self):
        current = {"_ref": "network/n:10.0.0.0/24/default", "network": "10.0.0.0/24", "network_view": "default", "comment": "old"}
        appliance, session = api(page([current]), Response({**current, "comment": ""}))
        result = client.execute_with_client("network_upsert", {"network": "10.0.0.0/24", "comment": ""}, appliance)
        self.assertTrue(result["changed"])
        self.assertEqual({"comment": ""}, session.calls[1][2]["json"])

    def test_search_controls_fields_and_address_filters(self):
        appliance, session = api(page([]))
        result = client.execute_with_client("address_search", {
            "family": "ipv6", "address": "2001:0db8::1", "network": "2001:db8::7/64",
            "return_fields": ["ip_address", "status"], "page_size": 20, "max_pages": 2,
        }, appliance)
        self.assertEqual(0, result["count"])
        params = session.calls[0][2]["params"]
        self.assertEqual("2001:db8::1", params["ip_address"])
        self.assertEqual("2001:db8::/64", params["network"])
        self.assertEqual("ip_address,status", params["_return_fields"])


class CredentialAndEntryPointTests(unittest.TestCase):
    def test_key_lookup_requests_decryption(self):
        calls = {}
        parsed = types.SimpleNamespace(data=types.SimpleNamespace(value=json.dumps(config())))
        fake_attune = types.ModuleType("attune")
        fake_attune.context = types.SimpleNamespace(client="execution-client")
        fake_secrets = types.ModuleType("attune.api_client.api.secrets")
        fake_secrets.get_key = types.SimpleNamespace(sync_detailed=lambda ref, *, client, decrypt: calls.update(ref=ref, client=client, decrypt=decrypt) or types.SimpleNamespace(status_code=200, parsed=parsed))
        modules = {
            "attune": fake_attune,
            "attune.api_client": types.ModuleType("attune.api_client"),
            "attune.api_client.api": types.ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": fake_secrets,
        }
        with mock.patch.dict(sys.modules, modules):
            self.assertEqual("api-user", client._fetch_key("infoblox.credentials")["username"])
        self.assertEqual({"ref": "infoblox.credentials", "client": "execution-client", "decrypt": True}, calls)

    def test_entrypoint_structure_and_redaction(self):
        spec = importlib.util.spec_from_file_location("infoblox_action_test", ROOT / "actions" / "infoblox_action.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        def run(stdin, side_effect=None):
            stdout, stderr = io.StringIO(), io.StringIO()
            patcher = mock.patch.object(module, "execute_action", side_effect=side_effect) if side_effect else mock.patch.object(module, "execute_action", return_value={"count": 0})
            with patcher, mock.patch.dict(os.environ, {"ATTUNE_ACTION": "infoblox.network_list"}), mock.patch("sys.stdin", io.StringIO(stdin)), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                code = module.main()
            return code, stdout.getvalue(), stderr.getvalue()

        code, stdout, stderr = run("{}")
        self.assertEqual(0, code)
        self.assertEqual({"operation": "network_list", "result": {"count": 0}}, json.loads(stdout))
        self.assertEqual("", stderr)
        code, stdout, stderr = run('{"password":"DO_NOT_PRINT"', RuntimeError("synthetic-secret"))
        self.assertEqual(1, code)
        self.assertEqual("", stdout)
        self.assertNotIn("DO_NOT_PRINT", stderr)
        code, _, stderr = run("{}", RuntimeError("synthetic-secret response"))
        self.assertEqual(1, code)
        self.assertNotIn("synthetic-secret", stderr)


if __name__ == "__main__":
    unittest.main()
