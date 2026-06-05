# TODO — review findings and action plan

Source: full code review + test/coverage run (2026-06-05). Unit suite green offline;
TLS acceptance suite green. Items ordered by priority within each section.

Note (2026-06-05): the STIG/NSS compliance engine was removed entirely
(`internal/provider/validators/`, `stig_compliance` provider block, NSS modes,
STIG docs/examples/tests) — all STIG-related findings below are closed as obsolete.

## 1. Correctness bugs

- [ ] **Zone update silently ignores DNSSEC parameter changes** — `internal/provider/zone_resource.go` (Update only handles sign/unsign). Changing `dnssec.algorithm`, `dnssec.curve`, or `dnssec.nx_proof` on an already-signed zone applies nothing; apply reports success and values revert on next read. Either implement re-sign/re-key via the API, mark those attributes `RequiresReplace`, or fail the plan with a clear error.
- [ ] **Zone update can't reset removed list attributes** — `internal/provider/zone_resource.go` (`setZoneOptions` skips null attrs). Deleting `notify`, `allow_transfer`, or `zone_transfer_tsig_key_names` from config sends nothing, so the server keeps the old values and state drifts. Define null semantics (reset to server default) and send the corresponding option.
- [x] **`exportFilteredZones` ignores HTTP status** — fixed: non-200 responses error out, and HTTP-200 JSON error envelopes (e.g. `invalid-token`) surface as `APIError`. Covered by unit tests in `internal/client/blocked_test.go`.
- [ ] **Record Read never resets type-specific attrs** — `internal/provider/record_resource.go`. `priority`, `weight`, `port`, `caa_flags`, `caa_tag` are only overwritten when present in rData, never cleared to null — Read is not a faithful refresh. Mirror `zone_resource.go`'s explicit null-or-value pattern.
- [ ] **Record import sets `overwrite=false`, schema default is `true`** — `internal/provider/record_resource.go`. First plan after import shows a cosmetic `overwrite: false -> true` diff. Align the import default with the schema default.
- [ ] **Create/Update don't reconcile server-normalized values** — `internal/provider/record_resource.go`. Only `LastModified` is copied from the read-back; server-normalized TTL/value (e.g. IPv6 compression) cause perpetual diffs. Refresh state from the matched server record.
- [ ] **Verify CNAME update semantics against the API** — `internal/provider/record_resource.go`. CNAME is the only type that sends just the new value (no current value to locate the record). Confirm Technitium's single-CNAME semantics make this correct; add an acceptance test for in-place CNAME value change.
- [x] ~~`validateZoneTSIGKeyNames` null handling~~ — obsolete: STIG engine removed.
- [ ] **Record data source errors on zero matches** — `internal/provider/record_data_source.go`. Hard "No records found" error instead of an empty list; diverges from normal data-source semantics and prevents absence checks.

## 2. Security / hygiene

- [x] **Remove hardcoded fallback API token** — done: `testAccAPIToken` now reads only `TECHNITIUM_API_TOKEN` and panics with guidance when `TF_ACC` is armed without a token.
- [x] ~~STIG baseline provenance~~ — obsolete: STIG engine (including `stig_baselines` data and the stub generator) removed.
- [x] **Token in URL query string** — done: all API calls (including the plain-text export endpoints) now POST with the token form-encoded in the request body; locked in by unit tests asserting the token never appears in a URL.
- [x] **Dead branch in `providerConfigAccessor`** — obsolete: the accessor was deleted with the STIG engine (and the TLS-min-version branch was fixed before removal).

## 3. Test coverage

- [ ] **`internal/client` unit tests — biggest gap**. `blocked.go`/`allowed.go` export paths now covered (`blocked_test.go`); still no tests for `zones.go`, `records.go`, `settings.go`, `tsig.go`. Highest value: TSIG pipe-delimiter validation, idempotent-delete logic. Use `httptest` servers.
- [ ] **Acceptance tests for untested data sources** — `record`, `tsig_key`, `server_settings` (zone data source is covered in `zone_resource_test.go`).
- [ ] **`allowed_zones`/`blocked_zones` resources are not importable** — neither implements `ImportState` (singular variants do). Implement or document the limitation.
- [x] ~~Misleading validator test~~ — obsolete: STIG engine tests removed.
- [x] ~~`TFConfigAdapter` unit tests~~ — obsolete: adapter removed with the STIG engine.
