# TODO — review findings and action plan

Source: full code review + test/coverage run (2026-06-05). Unit suite green offline;
TLS acceptance suite green. Items ordered by priority within each section.

## 1. Correctness bugs

- [ ] **Zone update silently ignores DNSSEC parameter changes** — `internal/provider/zone_resource.go` (Update only handles sign/unsign). Changing `dnssec.algorithm`, `dnssec.curve`, or `dnssec.nx_proof` on an already-signed zone applies nothing; apply reports success and values revert on next read. Either implement re-sign/re-key via the API, mark those attributes `RequiresReplace`, or fail the plan with a clear error.
- [ ] **Zone update can't reset removed list attributes** — `internal/provider/zone_resource.go` (`setZoneOptions` skips null attrs). Deleting `notify`, `allow_transfer`, or `zone_transfer_tsig_key_names` from config sends nothing, so the server keeps the old values and state drifts. Define null semantics (reset to server default) and send the corresponding option.
- [ ] **Record Read never resets type-specific attrs** — `internal/provider/record_resource.go`. `priority`, `weight`, `port`, `caa_flags`, `caa_tag` are only overwritten when present in rData, never cleared to null — Read is not a faithful refresh. Mirror `zone_resource.go`'s explicit null-or-value pattern.
- [ ] **Record import sets `overwrite=false`, schema default is `true`** — `internal/provider/record_resource.go`. First plan after import shows a cosmetic `overwrite: false -> true` diff. Align the import default with the schema default.
- [ ] **Create/Update don't reconcile server-normalized values** — `internal/provider/record_resource.go`. Only `LastModified` is copied from the read-back; server-normalized TTL/value (e.g. IPv6 compression) cause perpetual diffs. Refresh state from the matched server record.
- [ ] **Verify CNAME update semantics against the API** — `internal/provider/record_resource.go`. CNAME is the only type that sends just the new value (no current value to locate the record). Confirm Technitium's single-CNAME semantics make this correct; add an acceptance test for in-place CNAME value change.
- [ ] **Record data source errors on zero matches** — `internal/provider/record_data_source.go`. Hard "No records found" error instead of an empty list; diverges from normal data-source semantics and prevents absence checks.

## 2. DHCP support (new feature)

API surface: `/api/dhcp/scopes/{list,get,set,enable,disable,delete,addReservedLease,removeReservedLease}`, `/api/dhcp/leases/{list,remove,convertToReserved,convertToDynamic}` (see `docs/technitium-apidocs.md`).

- [x] Client layer: `internal/client/dhcp.go` — scope get/set/list/enable/disable/delete + reserved lease add/remove + leases list/remove/convert, with `httptest` unit tests
- [x] Resource `technitium_dhcp_scope` — full schema (address range, subnet mask, lease time, offer delay, ping check, domain/search list, DNS updates/TTL, boot/TFTP/server options, router, DNS/WINS/NTP servers, static routes, exclusions, vendor info, CAPWAP, generic options, `allow_only_reserved_leases`, MAC-filtering flags) with `enabled` flag mapped to enable/disable endpoints
- [x] Resource `technitium_dhcp_scope`: rename support (in-place via `newName`; id recomputed) + `ImportState`
- [x] Resource `technitium_dhcp_reserved_lease` — standalone reservation (scope, MAC, IP, hostname, comments) via addReservedLease/removeReservedLease; define conflict semantics vs inline scope `reserved_leases`
- [x] Data source `technitium_dhcp_scope` (single) and `technitium_dhcp_scopes` (list)
- [x] Data source `technitium_dhcp_leases` — runtime lease table (address, MAC, hostname, type, expiry)
- [x] Input validation (ValidateConfig on both resources): MAC address format, IPv4 range ordering (start <= end), exclusion ranges inside scope range, static-route triplets
- [x] Register all new resources/data sources in `provider.go`
- [x] Examples (`examples/resources|data-sources/technitium_dhcp_*`) + generated docs (`make docs`)
- [x] E2E acceptance tests: scope lifecycle (create → read → update → enable/disable → import → delete), reserved lease add/remove + convert flows, scopes/leases data sources — green in both HTTP (`make testacc-up`) and TLS (`make testacc-up-tls`) suites
- [x] Verify the docker test container accepts scope config without a bindable interface for the scope range (config-only tests; DHCP port 67/udp not required) — confirmed: no compose changes needed (server even auto-enables new scopes; the resource reconciles to the planned enabled state)

## 3. Test coverage

- [x] **`internal/client` unit tests** — done: 45 new tests across `zones_test.go`, `records_test.go`, `settings_test.go`, `tsig_test.go` (TSIG pipe-delimiter validation, idempotent delete, wire formats, DNSSEC paths). Package coverage 26% → 80.7%.
- [x] **Acceptance tests for data sources** — already existed inside the resource test files (`TestAccRecordDataSource`, `TestAccTSIGKeyDataSource_basic`, `TestAccServerSettingsDataSource`); the original review missed them because there are no dedicated `*_data_source_test.go` files. Verified green.
- [x] **`allowed_zones`/`blocked_zones` import** — done: `ImportState` takes a comma-separated domain list (the server-side list has no per-set identity) and generates a fresh UUID id; import acceptance steps added to both basic tests.
