# Infoblox NIOS Attune pack

Production-oriented IPAM, DHCP fixed-address, and authoritative DNS actions for
the versioned Infoblox NIOS Web API (WAPI). This translation retains the useful
coverage of the upstream StackStorm pack while replacing its broad generated
object wrappers, workflows, disabled TLS defaults, and `infoblox-client`
dependency with a small direct HTTP client and explicit safety contracts.

## Credentials and transport

Create the pack-owned Attune Key `infoblox.credentials` with an object value:

```json
{
  "base_url": "https://grid.example.net",
  "username": "attune-api",
  "password": "REDACTED",
  "wapi_version": "2.13.7",
  "connect_timeout_seconds": 5,
  "read_timeout_seconds": 30,
  "ca_bundle": "/optional/absolute/path/to/private-ca.pem"
}
```

`base_url` may contain a reverse-proxy prefix but must not contain `/wapi/`, a
query, fragment, or user information. The client appends
`/wapi/v{wapi_version}`. HTTPS and certificate verification are mandatory;
verification cannot be disabled. The system trust store is used unless an
absolute `ca_bundle` is supplied. Connect timeouts are bounded to 1-30 seconds
and read timeouts to 1-300 seconds.

Credentials use HTTP Basic authentication through `requests` and exist only in
the Attune Key and request authentication tuple. Actions never accept them as
parameters. Redirects are disabled. Errors include only the HTTP method/status
or exception class, never request URLs, headers, authentication, response
bodies, server traces, certificate paths, or underlying exception messages.

Grant the WAPI account only the object permissions needed by the actions used.

## Actions

| Action | Behavior |
|---|---|
| `infoblox.network_view_list` | List network views with bounded paging |
| `infoblox.network_view_upsert` | Create by exact name or update supplied comment |
| `infoblox.network_view_delete` | Delete a non-default view after exact-name confirmation |
| `infoblox.network_list` | List IPv4 or IPv6 networks in one network view |
| `infoblox.network_upsert` | Create by normalized CIDR/view or update comment/disable |
| `infoblox.network_delete` | Delete one exact CIDR/view after normalized-CIDR confirmation |
| `infoblox.address_search` | Search read-only IPv4/IPv6 IPAM address objects |
| `infoblox.next_available_ip` | Discover non-reserved candidate addresses |
| `infoblox.fixed_address_list` | List IPv4 or IPv6 fixed addresses |
| `infoblox.fixed_address_upsert` | Create/update an explicit fixed address |
| `infoblox.fixed_address_allocate` | Atomically select and create a fixed address |
| `infoblox.fixed_address_delete` | Delete an exact fixed address after confirmation |
| `infoblox.dns_view_list` | List DNS views with bounded paging |
| `infoblox.dns_view_upsert` | Create a DNS view or update comment/disable |
| `infoblox.dns_view_delete` | Delete a non-default DNS view after confirmation |
| `infoblox.zone_list` | List authoritative forward/reverse zones |
| `infoblox.zone_upsert` | Create a zone or update comment/disable |
| `infoblox.zone_delete` | Delete an exact zone/view and its records after confirmation |
| `infoblox.record_list` | List A, AAAA, CNAME, or PTR records |
| `infoblox.record_upsert` | Create/update one exact A, AAAA, CNAME, or PTR record |
| `infoblox.record_delete` | Delete one exact record after value confirmation |

Every action accepts one flat stdin JSON object and returns a stable envelope:

```json
{"operation":"network_list","result":{"items":[],"count":0,"pages_fetched":1,"truncated":false,"next_page_id":null}}
```

## Paging and fields

List/search actions use WAPI `_paging=1`, `_return_as_object=1`, and a positive
`_max_results`. `page_size` is 1-1000 (default 200); `max_pages` is 1-50
(default 10). Results report `pages_fetched`, `truncated`, and the last
`next_page_id` when truncated. A repeated or malformed page identifier fails
closed. WAPI documents each page as an independent request, so objects added or
removed during a traversal can cause a non-snapshot result.

`return_fields` accepts at most 50 validated WAPI field names and maps to
`_return_fields`. Omit it for each object's basic fields. `_ref` is always
returned by WAPI and is requested/handled internally rather than accepted as an
operator-selected field. Query values are passed through `requests` parameters,
not interpolated into URLs, so names containing reserved characters are
percent-encoded by the HTTP library.

## Mutation safety

Upserts first search by a documented exact identity. Zero matches creates, one
match compares only supplied mutable fields and updates only differences, and
multiple matches fail without mutation. Create-only fields are never silently
applied to an existing object. An uncertain timeout can be retried: the exact
lookup normally discovers a completed first request and returns `changed:
false`. Mutations themselves are never automatically retried.

Delete actions require `confirm: true` plus an exact identity confirmation.
They search first, treat absence as a successful no-op, reject ambiguous
matches, and delete only the `_ref` returned by that lookup. The client validates
the reference type and reduces the appliance reference to its documented opaque
`object-type/refdata` form, discarding the descriptive name suffix. Operators
cannot submit arbitrary references. Default network and DNS views are refused.
Zone deletion removes the selected zone and its contained records. Network and
view deletion is submitted only for the exact selected object; NIOS remains
responsible for rejecting dependencies that prevent deletion. Record deletion
does not send `remove_associated_ptr`, so it does not opt into the optional
associated-record side effect.

DNS record values are type checked. A/AAAA owner names and PTR addresses can
legitimately have multiple values. To change one value, pass `current_value`;
without it, an exact desired value is idempotently retained or a new value is
created. CNAME is identified by owner/view. PTR also requires its source
`address` and supports both IPv4 and IPv6. `ttl` sets both `ttl` and `use_ttl:
true`; omitting it preserves existing inheritance behavior.

## Allocation races

`next_available_ip` calls the network function and returns `reserved: false`.
It is discovery only: another actor can consume any returned address immediately
after the response. Never use its output as proof of reservation.

`fixed_address_allocate` instead supplies an inline `next_available_ip` function
as the address field of the fixed-address POST. NIOS performs selection as part
of insertion, avoiding the select-then-create address race. The action first
checks the exact network, network view, and stable client identifier, so normal
reruns are idempotent. WAPI does not expose a client-provided idempotency key or
conditional create for this operation: two concurrent first calls using the
same MAC/DUID can both pass the preflight and may create separate objects if the
appliance permits it. Serialize allocation per client identifier externally.
The inline insertion still ensures each successfully created object receives an
address that was available at its own insertion point.

## WAPI compatibility

Behavior was checked on 2026-08-14 against the Infoblox WAPI 2.13.7 reference,
copyright 2025. That reference states that WAPI versions are independent of
NIOS versions, current same-major versions emulate older supported behavior,
HTTPS is the transport, HTTP status is authoritative for errors, and new fields
may appear. Configure the version expected by your appliance and policy; the
pack defaults to `2.13.7` but validates any numeric dot-separated version.

The current reference confirms the object and field names used here:
`networkview`, `network`, `ipv6network`, `ipv4address`, `ipv6address`,
`fixedaddress`, `ipv6fixedaddress`, `view`, `zone_auth`, `record:a`,
`record:aaaa`, `record:cname`, and `record:ptr`. IPAM address objects are
read-only. WAPI POST/PUT can return either an object or reference, both of which
the client handles. Object references are opaque and descriptive suffixes are
not identities.

## Source and scope

Upstream: [StackStorm-Exchange/stackstorm-infoblox](https://github.com/StackStorm-Exchange/stackstorm-infoblox),
version/tag `1.1.1`/`v1.1.1`, revision
`49ab61fed17ed05bb72b4c4506890f88aa873569`, Apache-2.0. Exact provenance and
API-reference metadata are in `SOURCE.json`.

The upstream generic object actions and broad generated YAML files were not
copied. Network/network-view/view, fixed-address, address search, zone, and
A/AAAA/CNAME/PTR behavior was translated into typed contracts. Host records,
ranges, extensible-attribute definitions, members, service restart, arbitrary
objects, raw references/payloads, and orchestration workflows remain outside
this initial safety-focused surface.

## Live-test gaps

- No live NIOS appliance or credentials are bundled; RBAC, Grid topology,
  member restart requirements, approval workflows, and Cloud Platform
  restrictions need environment-specific validation.
- Zone creation may require `ns_group`, `grid_primary`, or external server
  structures depending on deployment policy; this initial action intentionally
  does not expose arbitrary server structures.
- Reverse-zone format and RFC2317 policy vary by deployment and need live tests.
- Concurrent same-client fixed-address allocation requires external locking as
  described above.
- Certificate chains using a private CA require a runtime-visible absolute
  `ca_bundle` path.

## Testing

Tests use only the Python standard library plus an import shim when `requests`
is absent. Every HTTP session is mocked; tests make no appliance, DNS, Attune
API, or other network calls.

```bash
python -m unittest discover -s tests -v
python -m compileall -q actions lib tests
attune --output json pack check .
attune pack test . --detailed
```
