"""Direct, bounded Infoblox NIOS WAPI client and action dispatch."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit


class InfobloxPackError(RuntimeError):
    """Safe operator-facing error that never includes remote response content."""


_MISSING = object()
_WAPI_VERSION = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*$")
_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_OBJECT_TYPES = {
    "networkview", "network", "ipv6network", "ipv4address", "ipv6address",
    "fixedaddress", "ipv6fixedaddress", "view", "zone_auth", "record:a",
    "record:aaaa", "record:cname", "record:ptr",
}
_RECORDS = {
    "A": ("record:a", "ipv4addr"),
    "AAAA": ("record:aaaa", "ipv6addr"),
    "CNAME": ("record:cname", "canonical"),
    "PTR": ("record:ptr", "ptrdname"),
}


def _fetch_key(ref: str) -> dict[str, Any]:
    if not isinstance(ref, str) or not ref.strip():
        raise InfobloxPackError("credential_key must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key
    except ImportError as exc:
        raise InfobloxPackError("attune-sdk is required to resolve credential_key") from exc
    try:
        response = get_key.sync_detailed(ref, client=attune.context.client, decrypt=True)
    except Exception as exc:
        raise InfobloxPackError(f"unable to read credential Key {ref!r}") from exc
    status = int(response.status_code)
    if status == 404:
        raise InfobloxPackError(f"credential Key {ref!r} was not found")
    if status >= 400 or not response.parsed:
        raise InfobloxPackError(f"credential Key lookup failed with status {status}")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise InfobloxPackError("credential Key must contain a JSON object") from exc
    if not isinstance(value, dict):
        raise InfobloxPackError("credential Key must contain an object")
    return value


def _text(value: Any, name: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise InfobloxPackError(f"{name} must be a non-empty string without surrounding whitespace")
    if len(value) > maximum or any(ord(character) < 32 for character in value):
        raise InfobloxPackError(f"{name} is invalid or too long")
    return value


def _optional_text(params: Mapping[str, Any], name: str, *, maximum: int = 1024) -> str | None:
    return _text(params[name], name, maximum=maximum) if params.get(name) is not None else None


def _boolean(params: Mapping[str, Any], name: str, default: bool | None = None) -> bool | None:
    value = params.get(name, default)
    if value is not None and not isinstance(value, bool):
        raise InfobloxPackError(f"{name} must be a boolean")
    return value


def _integer(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < low or value > high:
        raise InfobloxPackError(f"{name} must be an integer between {low} and {high}")
    return value


def _number(value: Any, name: str, default: float, low: float, high: float) -> float:
    value = default if value is None else value
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InfobloxPackError(f"{name} must be a number")
    result = float(value)
    if not math.isfinite(result) or result < low or result > high:
        raise InfobloxPackError(f"{name} must be between {low:g} and {high:g}")
    return result


def _family(params: Mapping[str, Any]) -> str:
    value = params.get("family", "ipv4")
    if value not in {"ipv4", "ipv6"}:
        raise InfobloxPackError("family must be ipv4 or ipv6")
    return value


def _network(value: Any, family: str, name: str = "network") -> str:
    try:
        parsed = ipaddress.ip_network(_text(value, name), strict=False)
    except ValueError as exc:
        raise InfobloxPackError(f"{name} must be a valid {family.upper()} CIDR network") from exc
    expected = 4 if family == "ipv4" else 6
    if parsed.version != expected:
        raise InfobloxPackError(f"{name} must be a valid {family.upper()} CIDR network")
    return str(parsed)


def _address(value: Any, family: str, name: str = "address") -> str:
    try:
        parsed = ipaddress.ip_address(_text(value, name))
    except ValueError as exc:
        raise InfobloxPackError(f"{name} must be a valid {family.upper()} address") from exc
    expected = 4 if family == "ipv4" else 6
    if parsed.version != expected:
        raise InfobloxPackError(f"{name} must be a valid {family.upper()} address")
    return str(parsed)


def _dns_name(value: Any, name: str) -> str:
    result = _text(value, name, maximum=255)
    if any(character.isspace() for character in result):
        raise InfobloxPackError(f"{name} must be a DNS name without whitespace")
    return result


def _fields(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 50:
        raise InfobloxPackError("return_fields must be an array of at most 50 field names")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _FIELD.fullmatch(item):
            raise InfobloxPackError("return_fields contains an invalid field name")
        if item in result:
            raise InfobloxPackError("return_fields must not contain duplicates")
        result.append(item)
    return result


def _settings(config: Mapping[str, Any]) -> tuple[str, str, str, tuple[float, float], Any]:
    base_url = config.get("base_url") or config.get("url")
    username = config.get("username")
    password = config.get("password")
    if not isinstance(base_url, str):
        raise InfobloxPackError("credential Key requires base_url")
    if not isinstance(username, str) or not username:
        raise InfobloxPackError("credential Key requires username")
    if not isinstance(password, str) or not password:
        raise InfobloxPackError("credential Key requires password")
    if base_url != base_url.strip() or any(ord(character) < 32 for character in base_url):
        raise InfobloxPackError("base_url is invalid")
    try:
        parts = urlsplit(base_url.rstrip("/"))
        _ = parts.port
    except ValueError as exc:
        raise InfobloxPackError("base_url is not a valid URL") from exc
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise InfobloxPackError("base_url must be an HTTPS URL without user information")
    if parts.query or parts.fragment or "/wapi/" in parts.path.rstrip("/"):
        raise InfobloxPackError("base_url must not contain a query, fragment, or WAPI version path")
    version = config.get("wapi_version", "2.13.7")
    if not isinstance(version, str) or not _WAPI_VERSION.fullmatch(version):
        raise InfobloxPackError("wapi_version must contain only numeric dot-separated components")
    if config.get("verify_tls", True) is not True:
        raise InfobloxPackError("TLS certificate verification cannot be disabled")
    ca_bundle = config.get("ca_bundle")
    if ca_bundle is not None and (not isinstance(ca_bundle, str) or not os.path.isabs(ca_bundle)):
        raise InfobloxPackError("ca_bundle must be an absolute path")
    timeout = (
        _number(config.get("connect_timeout_seconds"), "connect_timeout_seconds", 5, 1, 30),
        _number(config.get("read_timeout_seconds"), "read_timeout_seconds", 30, 1, 300),
    )
    return base_url.rstrip("/"), username, password, timeout, ca_bundle or True


class InfobloxClient:
    """Small direct client for versioned NIOS WAPI v2 endpoints."""

    def __init__(self, config: Mapping[str, Any], *, session: Any = None):
        import requests

        base_url, username, password, self.timeout, self.verify = _settings(config)
        self.wapi_version = config.get("wapi_version", "2.13.7")
        self.api_root = f"{base_url}/wapi/v{self.wapi_version}"
        self.auth = (username, password)
        self.session = session or requests.Session()

    @staticmethod
    def canonical_ref(value: Any, expected_type: str) -> str:
        if expected_type not in _OBJECT_TYPES or not isinstance(value, str):
            raise InfobloxPackError("Infoblox returned an invalid object reference")
        match = re.match(rf"^{re.escape(expected_type)}/([A-Za-z0-9_-]+)(?::|$)", value)
        if not match:
            raise InfobloxPackError("Infoblox returned an unexpected object reference type")
        return f"{expected_type}/{match.group(1)}"

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        body: Any = _MISSING,
        allow_not_found: bool = False,
    ) -> Any:
        import requests

        if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
            raise InfobloxPackError("invalid internal WAPI path")
        kwargs: dict[str, Any] = {
            "headers": {"Accept": "application/json"},
            "auth": self.auth,
            "params": dict(params) if params else None,
            "timeout": self.timeout,
            "verify": self.verify,
            "allow_redirects": False,
        }
        if body is not _MISSING:
            kwargs["headers"]["Content-Type"] = "application/json"
            kwargs["json"] = body
        try:
            response = self.session.request(method, self.api_root + path, **kwargs)
        except (requests.RequestException, OSError) as exc:
            raise InfobloxPackError(f"Infoblox WAPI {method} transport failed ({type(exc).__name__})") from exc
        status = int(response.status_code)
        if allow_not_found and status == 404:
            return None
        if status < 200 or status >= 300:
            raise InfobloxPackError(f"Infoblox WAPI {method} failed with HTTP status {status}")
        if status == 204 or not getattr(response, "content", b"x"):
            return None
        try:
            return response.json()
        except (ValueError, TypeError) as exc:
            raise InfobloxPackError("Infoblox WAPI returned invalid JSON") from exc

    def search(
        self,
        object_type: str,
        filters: Mapping[str, Any],
        *,
        return_fields: list[str] | None = None,
        page_size: int = 200,
        max_pages: int = 10,
    ) -> dict[str, Any]:
        if object_type not in _OBJECT_TYPES:
            raise InfobloxPackError("unsupported internal WAPI object type")
        page_size = _integer(page_size, "page_size", 1, 1000)
        max_pages = _integer(max_pages, "max_pages", 1, 50)
        params: dict[str, Any] = {
            **filters,
            "_paging": 1,
            "_return_as_object": 1,
            "_max_results": page_size,
        }
        if return_fields is not None:
            params["_return_fields"] = ",".join(field for field in return_fields if field != "_ref")
        items: list[dict[str, Any]] = []
        pages = 0
        next_page_id: str | None = None
        seen_page_ids: set[str] = set()
        while pages < max_pages:
            if next_page_id is not None:
                params["_page_id"] = next_page_id
            value = self.request("GET", f"/{object_type}", params=params)
            if not isinstance(value, dict) or not isinstance(value.get("result"), list):
                raise InfobloxPackError("Infoblox WAPI returned an invalid paging response")
            if not all(isinstance(item, dict) for item in value["result"]):
                raise InfobloxPackError("Infoblox WAPI returned invalid objects")
            items.extend(value["result"])
            pages += 1
            raw_next = value.get("next_page_id")
            if raw_next is not None and (not isinstance(raw_next, str) or not raw_next or len(raw_next) > 4096):
                raise InfobloxPackError("Infoblox WAPI returned an invalid next page identifier")
            next_page_id = raw_next
            if not next_page_id:
                break
            if next_page_id in seen_page_ids:
                raise InfobloxPackError("Infoblox WAPI repeated a paging identifier")
            seen_page_ids.add(next_page_id)
        return {
            "items": items,
            "count": len(items),
            "pages_fetched": pages,
            "truncated": bool(next_page_id),
            "next_page_id": next_page_id if next_page_id else None,
        }

    def exact(self, object_type: str, filters: Mapping[str, Any], fields: Iterable[str]) -> dict[str, Any] | None:
        result = self.search(object_type, filters, return_fields=list(dict.fromkeys(fields)), page_size=2, max_pages=1)
        if result["truncated"] or result["count"] > 1:
            raise InfobloxPackError(f"exact {object_type} identity matched multiple objects")
        return result["items"][0] if result["items"] else None

    def read_ref(self, reference: Any, object_type: str, fields: Iterable[str]) -> dict[str, Any]:
        ref = self.canonical_ref(reference, object_type)
        params = {"_return_fields": ",".join(field for field in dict.fromkeys(fields) if field != "_ref")}
        value = self.request("GET", f"/{ref}", params=params)
        if not isinstance(value, dict):
            raise InfobloxPackError("Infoblox WAPI returned an invalid object response")
        return value

    def create(self, object_type: str, body: Mapping[str, Any], fields: Iterable[str]) -> dict[str, Any]:
        field_list = list(dict.fromkeys([*fields, "_ref"]))
        value = self.request("POST", f"/{object_type}", params={"_return_fields": ",".join(field for field in field_list if field != "_ref")}, body=dict(body))
        if isinstance(value, dict):
            return value
        return self.read_ref(value, object_type, field_list)

    def update(self, reference: Any, object_type: str, body: Mapping[str, Any], fields: Iterable[str]) -> dict[str, Any]:
        ref = self.canonical_ref(reference, object_type)
        field_list = list(dict.fromkeys([*fields, "_ref"]))
        value = self.request("PUT", f"/{ref}", params={"_return_fields": ",".join(field for field in field_list if field != "_ref")}, body=dict(body))
        if isinstance(value, dict):
            return value
        return self.read_ref(value or ref, object_type, field_list)

    def delete(self, reference: Any, object_type: str) -> str:
        ref = self.canonical_ref(reference, object_type)
        self.request("DELETE", f"/{ref}")
        return ref


def _page(client: InfobloxClient, object_type: str, filters: Mapping[str, Any], params: Mapping[str, Any]) -> dict[str, Any]:
    return client.search(
        object_type,
        filters,
        return_fields=_fields(params.get("return_fields")),
        page_size=params.get("page_size", 200),
        max_pages=params.get("max_pages", 10),
    )


def _mutable(params: Mapping[str, Any], names: Iterable[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in names:
        if params.get(name) is not None:
            value = params[name]
            if name in {"comment", "name", "ns_group"}:
                if not isinstance(value, str) or len(value) > 256 or any(ord(character) < 32 for character in value):
                    raise InfobloxPackError(f"{name} is invalid or too long")
                if value and value != value.strip():
                    raise InfobloxPackError(f"{name} must not have surrounding whitespace")
            elif name == "disable" and not isinstance(value, bool):
                raise InfobloxPackError("disable must be a boolean")
            result[name] = value
    return result


def _upsert(
    client: InfobloxClient,
    object_type: str,
    identity: Mapping[str, Any],
    create: Mapping[str, Any],
    mutable: Mapping[str, Any],
) -> dict[str, Any]:
    fields = list(dict.fromkeys([*identity, *create, *mutable, "_ref"]))
    current = client.exact(object_type, identity, fields)
    if current is None:
        created = client.create(object_type, {**create, **mutable}, fields)
        return {"changed": True, "created": True, "object": created}
    changes = {name: value for name, value in mutable.items() if current.get(name) != value}
    if not changes:
        return {"changed": False, "created": False, "object": current}
    updated = client.update(current.get("_ref"), object_type, changes, fields)
    return {"changed": True, "created": False, "object": updated}


def _confirmed(params: Mapping[str, Any], field: str, expected: str) -> None:
    if params.get("confirm") is not True:
        raise InfobloxPackError("confirm must be true for deletion")
    if params.get(field) != expected:
        raise InfobloxPackError(f"{field} must exactly match the normalized object identity")


def _delete_exact(
    client: InfobloxClient,
    object_type: str,
    identity: Mapping[str, Any],
    params: Mapping[str, Any],
    confirm_field: str,
    confirm_value: str,
    fields: Iterable[str],
) -> dict[str, Any]:
    _confirmed(params, confirm_field, confirm_value)
    current = client.exact(object_type, identity, fields)
    if current is None:
        return {"changed": False, "deleted": False, "reason": "object not found", "identity": dict(identity)}
    ref = client.delete(current.get("_ref"), object_type)
    return {"changed": True, "deleted": True, "reference": ref, "identity": dict(identity)}


def _network_type(family: str) -> str:
    return "network" if family == "ipv4" else "ipv6network"


def _fixed_type(family: str) -> tuple[str, str]:
    return ("fixedaddress", "ipv4addr") if family == "ipv4" else ("ipv6fixedaddress", "ipv6addr")


def _client_identity(params: Mapping[str, Any], family: str) -> tuple[str, str, str]:
    value = _text(params.get("client_identifier"), "client_identifier", maximum=256)
    if family == "ipv4":
        if not _MAC.fullmatch(value):
            raise InfobloxPackError("client_identifier must be a MAC address for IPv4 fixed addresses")
        return "mac", value.lower().replace("-", ":"), "MAC_ADDRESS"
    match_client = params.get("match_client", "DUID")
    if match_client not in {"DUID", "MAC_ADDRESS"}:
        raise InfobloxPackError("match_client must be DUID or MAC_ADDRESS for IPv6")
    if match_client == "MAC_ADDRESS" and not _MAC.fullmatch(value):
        raise InfobloxPackError("client_identifier must be a MAC address when match_client is MAC_ADDRESS")
    return ("mac_address", value.lower().replace("-", ":"), match_client) if match_client == "MAC_ADDRESS" else ("duid", value, match_client)


def _record_type(params: Mapping[str, Any]) -> tuple[str, str, str]:
    raw = params.get("record_type")
    if not isinstance(raw, str) or raw.upper() not in _RECORDS:
        raise InfobloxPackError("record_type must be A, AAAA, CNAME, or PTR")
    record_type = raw.upper()
    object_type, value_field = _RECORDS[record_type]
    return record_type, object_type, value_field


def _record_value(value: Any, record_type: str, name: str = "value") -> str:
    if record_type == "A":
        return _address(value, "ipv4", name)
    if record_type == "AAAA":
        return _address(value, "ipv6", name)
    return _dns_name(value, name)


def execute_with_client(operation: str, params: Mapping[str, Any], client: InfobloxClient) -> dict[str, Any]:
    network_view = _text(params.get("network_view", "default"), "network_view", maximum=256)
    dns_view = _text(params.get("view", "default"), "view", maximum=256)

    if operation == "network_view_list":
        filters = {"name": _text(params["name"], "name", maximum=256)} if params.get("name") is not None else {}
        return _page(client, "networkview", filters, params)
    if operation == "network_view_upsert":
        name = _text(params.get("name"), "name", maximum=256)
        return _upsert(client, "networkview", {"name": name}, {"name": name}, _mutable(params, ("comment",)))
    if operation == "network_view_delete":
        name = _text(params.get("name"), "name", maximum=256)
        _confirmed(params, "confirm_name", name)
        current = client.exact("networkview", {"name": name}, ("name", "is_default", "_ref"))
        if current is None:
            return {"changed": False, "deleted": False, "reason": "object not found", "identity": {"name": name}}
        if current.get("is_default") is True:
            raise InfobloxPackError("the default network view cannot be deleted")
        ref = client.delete(current.get("_ref"), "networkview")
        return {"changed": True, "deleted": True, "reference": ref, "identity": {"name": name}}

    if operation in {"network_list", "network_upsert", "network_delete", "next_available_ip"}:
        family = _family(params)
        object_type = _network_type(family)
        if operation == "network_list":
            filters: dict[str, Any] = {"network_view": network_view}
            if params.get("network") is not None:
                filters["network"] = _network(params["network"], family)
            return _page(client, object_type, filters, params)
        network = _network(params.get("network"), family)
        identity = {"network": network, "network_view": network_view}
        if operation == "network_upsert":
            create = dict(identity)
            if params.get("auto_create_reversezone") is not None:
                create["auto_create_reversezone"] = _boolean(params, "auto_create_reversezone")
            return _upsert(client, object_type, identity, create, _mutable(params, ("comment", "disable")))
        if operation == "network_delete":
            return _delete_exact(client, object_type, identity, params, "confirm_network", network, ("network", "network_view", "_ref"))
        current = client.exact(object_type, identity, ("network", "network_view", "_ref"))
        if current is None:
            raise InfobloxPackError("network was not found")
        num = _integer(params.get("num", 1), "num", 1, 100)
        exclude = params.get("exclude", [])
        if not isinstance(exclude, list) or len(exclude) > 100:
            raise InfobloxPackError("exclude must be an array of at most 100 addresses")
        body = {"num": num, "exclude": [_address(item, family, "exclude item") for item in exclude]}
        ref = client.canonical_ref(current.get("_ref"), object_type)
        value = client.request("POST", f"/{ref}", params={"_function": "next_available_ip"}, body=body)
        if not isinstance(value, dict) or not isinstance(value.get("ips"), list):
            raise InfobloxPackError("Infoblox returned an invalid next-available-IP response")
        return {
            "addresses": value["ips"],
            "reserved": False,
            "race_warning": "Discovery does not reserve addresses; use fixed_address_allocate for atomic allocation and creation.",
        }

    if operation == "address_search":
        family = _family(params)
        object_type = "ipv4address" if family == "ipv4" else "ipv6address"
        filters: dict[str, Any] = {"network_view": network_view}
        if params.get("address") is not None:
            filters["ip_address"] = _address(params["address"], family)
        if params.get("network") is not None:
            filters["network"] = _network(params["network"], family)
        for name in ("status", "lease_state"):
            if params.get(name) is not None:
                filters[name] = _text(params[name], name, maximum=64)
        if params.get("name") is not None:
            filters["names"] = _dns_name(params["name"], "name")
        return _page(client, object_type, filters, params)

    if operation in {"fixed_address_list", "fixed_address_upsert", "fixed_address_allocate", "fixed_address_delete"}:
        family = _family(params)
        object_type, address_field = _fixed_type(family)
        if operation == "fixed_address_list":
            filters: dict[str, Any] = {"network_view": network_view}
            if params.get("address") is not None:
                filters[address_field] = _address(params["address"], family)
            if params.get("network") is not None:
                filters["network"] = _network(params["network"], family)
            if params.get("client_identifier") is not None:
                field, identifier, _ = _client_identity(params, family)
                filters[field] = identifier
            return _page(client, object_type, filters, params)
        if operation == "fixed_address_delete":
            address = _address(params.get("address"), family)
            identity = {address_field: address, "network_view": network_view}
            return _delete_exact(client, object_type, identity, params, "confirm_address", address, (address_field, "network_view", "_ref"))
        field, identifier, match_client = _client_identity(params, family)
        if operation == "fixed_address_allocate":
            network = _network(params.get("network"), family)
            existing = client.exact(object_type, {"network": network, "network_view": network_view, field: identifier}, (address_field, "network", "network_view", field, "_ref"))
            if existing is not None:
                return {"changed": False, "created": False, "object": existing, "allocation": "atomic-inline"}
            network_object = _network_type(family)
            source = client.exact(network_object, {"network": network, "network_view": network_view}, ("network", "network_view", "_ref"))
            if source is None:
                raise InfobloxPackError("allocation network was not found")
            exclude = params.get("exclude", [])
            if not isinstance(exclude, list) or len(exclude) > 100:
                raise InfobloxPackError("exclude must be an array of at most 100 addresses")
            inline = {
                "_object_function": "next_available_ip",
                "_result_field": "ips",
                "_object_ref": client.canonical_ref(source.get("_ref"), network_object),
                "_parameters": {"exclude": [_address(item, family, "exclude item") for item in exclude]},
            }
            body = {address_field: inline, "network_view": network_view, field: identifier, "match_client": match_client}
            body.update(_mutable(params, ("comment", "name")))
            created = client.create(object_type, body, (address_field, "network", "network_view", field, "match_client", "comment", "name", "_ref"))
            return {"changed": True, "created": True, "object": created, "allocation": "atomic-inline"}
        address = _address(params.get("address"), family)
        identity = {address_field: address, "network_view": network_view}
        if operation == "fixed_address_upsert":
            mutable = {field: identifier, "match_client": match_client, **_mutable(params, ("comment", "name", "disable"))}
            return _upsert(client, object_type, identity, identity, mutable)
        raise InfobloxPackError("unsupported fixed-address operation")

    if operation == "dns_view_list":
        filters = {"name": _text(params["name"], "name", maximum=256)} if params.get("name") is not None else {}
        if params.get("network_view") is not None:
            filters["network_view"] = network_view
        return _page(client, "view", filters, params)
    if operation == "dns_view_upsert":
        name = _text(params.get("name"), "name", maximum=256)
        create = {"name": name, "network_view": network_view}
        if params.get("comment") is not None:
            comment = params["comment"]
            if not isinstance(comment, str) or len(comment) > 64 or any(ord(character) < 32 for character in comment):
                raise InfobloxPackError("comment is invalid or longer than 64 characters")
            if comment and comment != comment.strip():
                raise InfobloxPackError("comment must not have surrounding whitespace")
        return _upsert(client, "view", {"name": name}, create, _mutable(params, ("comment", "disable")))
    if operation == "dns_view_delete":
        name = _text(params.get("name"), "name", maximum=256)
        _confirmed(params, "confirm_name", name)
        current = client.exact("view", {"name": name}, ("name", "is_default", "_ref"))
        if current is None:
            return {"changed": False, "deleted": False, "reason": "object not found", "identity": {"name": name}}
        if current.get("is_default") is True:
            raise InfobloxPackError("the default DNS view cannot be deleted")
        ref = client.delete(current.get("_ref"), "view")
        return {"changed": True, "deleted": True, "reference": ref, "identity": {"name": name}}

    if operation in {"zone_list", "zone_upsert", "zone_delete"}:
        if operation == "zone_list":
            filters: dict[str, Any] = {"view": dns_view}
            if params.get("fqdn") is not None:
                filters["fqdn"] = _dns_name(params["fqdn"], "fqdn")
            return _page(client, "zone_auth", filters, params)
        fqdn = _dns_name(params.get("fqdn"), "fqdn")
        identity = {"fqdn": fqdn, "view": dns_view}
        if operation == "zone_upsert":
            create: dict[str, Any] = dict(identity)
            if params.get("zone_format") is not None:
                zone_format = params["zone_format"]
                if zone_format not in {"FORWARD", "IPV4", "IPV6"}:
                    raise InfobloxPackError("zone_format must be FORWARD, IPV4, or IPV6")
                create["zone_format"] = zone_format
            if params.get("ns_group") is not None:
                create["ns_group"] = _text(params["ns_group"], "ns_group", maximum=256)
            return _upsert(client, "zone_auth", identity, create, _mutable(params, ("comment", "disable")))
        return _delete_exact(client, "zone_auth", identity, params, "confirm_fqdn", fqdn, ("fqdn", "view", "_ref"))

    if operation in {"record_list", "record_upsert", "record_delete"}:
        record_type, object_type, value_field = _record_type(params)
        if operation == "record_list":
            filters: dict[str, Any] = {"view": dns_view}
            if params.get("name") is not None:
                filters["name"] = _dns_name(params["name"], "name")
            if params.get("value") is not None:
                filters[value_field] = _record_value(params["value"], record_type)
            if record_type == "PTR" and params.get("address") is not None:
                try:
                    parsed = ipaddress.ip_address(_text(params["address"], "address"))
                except ValueError as exc:
                    raise InfobloxPackError("address must be a valid IPv4 or IPv6 address") from exc
                filters["ipv4addr" if parsed.version == 4 else "ipv6addr"] = str(parsed)
            return _page(client, object_type, filters, params)
        value = _record_value(params.get("value"), record_type)
        if record_type == "PTR":
            try:
                parsed_address = ipaddress.ip_address(_text(params.get("address"), "address"))
            except ValueError as exc:
                raise InfobloxPackError("address must be a valid IPv4 or IPv6 address for PTR records") from exc
            address_field = "ipv4addr" if parsed_address.version == 4 else "ipv6addr"
            create = {address_field: str(parsed_address), "view": dns_view, value_field: value}
            current_value = params.get("current_value")
            identity = {
                address_field: str(parsed_address),
                "view": dns_view,
                value_field: _record_value(current_value, record_type, "current_value") if current_value is not None else value,
            }
        else:
            name = _dns_name(params.get("name"), "name")
            create = {"name": name, "view": dns_view, value_field: value}
            if record_type == "CNAME":
                identity = {"name": name, "view": dns_view}
            else:
                current_value = params.get("current_value")
                identity = {"name": name, "view": dns_view, value_field: _record_value(current_value, record_type, "current_value")} if current_value is not None else dict(create)
        mutable = {value_field: value}
        mutable.update(_mutable(params, ("comment", "disable")))
        if params.get("ttl") is not None:
            mutable["ttl"] = _integer(params["ttl"], "ttl", 0, 4294967295)
            mutable["use_ttl"] = True
        if operation == "record_delete":
            identity[value_field] = value
        fields = list(dict.fromkeys([*identity, *create, *mutable, "_ref"]))
        current = client.exact(object_type, identity, fields)
        if operation == "record_delete":
            _confirmed(params, "confirm_value", value)
            if current is None:
                return {"changed": False, "deleted": False, "reason": "record not found", "identity": identity}
            ref = client.delete(current.get("_ref"), object_type)
            return {"changed": True, "deleted": True, "reference": ref, "identity": identity}
        if current is None:
            created = client.create(object_type, {**create, **mutable}, fields)
            return {"changed": True, "created": True, "record": created}
        changes = {key: item for key, item in mutable.items() if current.get(key) != item}
        if not changes:
            return {"changed": False, "created": False, "record": current}
        updated = client.update(current.get("_ref"), object_type, changes, fields)
        return {"changed": True, "created": False, "record": updated}

    raise InfobloxPackError(f"unsupported Infoblox operation {operation!r}")


def execute_action(operation: str, params: Mapping[str, Any]) -> dict[str, Any]:
    credential_key = params.get("credential_key", "infoblox.credentials")
    return execute_with_client(operation, params, InfobloxClient(_fetch_key(credential_key)))
