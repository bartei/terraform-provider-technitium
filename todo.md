# TODO — review findings and action plan

Source: full code review + test/coverage run (2026-06-05). Unit suite green offline;
TLS acceptance suite green (66.7% total statement coverage). Items ordered by priority
within each section.

## 1. Correctness bugs

- [ ] **Zone update silently ignores DNSSEC parameter changes** — `internal/provider/zone_resource.go` (Update only handles sign/unsign). Changing `dnssec.algorithm`, `dnssec.curve`, or `dnssec.nx_proof` on an already-signed zone applies nothing; apply reports success and values revert on next read. Either implement re-sign/re-key via the API, mark those attributes `RequiresReplace`, or fail the plan with a clear error.
- [ ] **Zone update can't reset removed list attributes** — `internal/provider/zone_resource.go` (`setZoneOptions` skips null attrs). Deleting `notify`, `allow_transfer`, or `zone_transfer_tsig_key_names` from config sends nothing, so the server keeps the old values and state drifts. Define null semantics (reset to server default) and send the corresponding option.
- [ ] **`exportFilteredZones` ignores HTTP status** — `internal/client/blocked.go:34` (also used by allowed zones). A 401/500/HTML error body is parsed line-by-line as a domain list, silently corrupting state. Check `resp.StatusCode` and detect a JSON error envelope before parsing.
- [ ] **Record Read never resets type-specific attrs** — `internal/provider/record_resource.go:203-257`. `priority`, `weight`, `port`, `caa_flags`, `caa_tag` are only overwritten when present in rData, never cleared to null — Read is not a faithful refresh. Mirror `zone_resource.go`'s explicit null-or-value pattern.
- [ ] **Record import sets `overwrite=false`, schema default is `true`** — `internal/provider/record_resource.go:355`. First plan after import shows a cosmetic `overwrite: false -> true` diff. Align the import default with the schema default.
- [ ] **Create/Update don't reconcile server-normalized values** — `internal/provider/record_resource.go:282-292`. Only `LastModified` is copied from the read-back; server-normalized TTL/value (e.g. IPv6 compression) cause perpetual diffs. Refresh state from the matched server record.
- [ ] **Verify CNAME update semantics against the API** — `internal/provider/record_resource.go:439`. CNAME is the only type that sends just the new value (no current value to locate the record). Confirm Technitium's single-CNAME semantics make this correct; add an acceptance test for in-place CNAME value change.
- [ ] **`validateZoneTSIGKeyNames` null handling diverges from convention** — `internal/provider/validators/stig.go:364-370`. Returns compliant on null instead of producing a finding (or doing the documented `IsUnknown` dance like `validateZoneTransferNetworks`). Decide intended behavior for DNS-REQ-002 and align + document.
- [ ] **Record data source errors on zero matches** — `internal/provider/record_data_source.go:131-136`. Hard "No records found" error instead of an empty list; diverges from normal data-source semantics and prevents absence checks.

## 2. Security / hygiene

- [ ] **Remove hardcoded fallback API token** — `internal/provider/zone_resource_test.go:596-605` (`testAccAPIToken` falls back to a committed 64-hex token). Fail/skip when `TECHNITIUM_API_TOKEN` is unset instead.
- [ ] **STIG baseline provenance is self-contradictory** — `internal/provider/validators/stig_baselines_gen.go`: header claims V3R2/V2R4 (2026-05-23), `GeneratedAt` says 2026-03-19, `GeneratedFrom` says V3R1/V2R3. The generator (`tools/generate_stig_baselines.go`) is a stub that writes nothing, so drift is permanent. Fix the metadata and either implement the generator or remove the stub + `make generate-stig`.
- [ ] **Token in URL query string** — `internal/client/` (all request paths). Tokens in URLs leak into proxy/server logs. Low priority (consistent with Technitium API design), but consider a header/body if the API supports it.
- [ ] **Dead branch** — `internal/provider/provider.go:602-606`: `tlsMinVersion == ""` is unreachable (`resolveTLSMinVersion` always returns non-empty). Remove the misleading skip path.

## 3. Test coverage

- [ ] **`internal/client` unit tests — biggest gap (26.2%)**. No tests at all for `zones.go`, `records.go`, `settings.go`, `tsig.go`, `allowed.go`, `blocked.go`. Highest value: export status-code edge case (bug above), TSIG pipe-delimiter validation, idempotent-delete logic. Use `httptest` servers.
- [ ] **Acceptance tests for the four untested data sources** — `record`, `zone`, `tsig_key`, `server_settings` (no `_test.go` counterparts).
- [ ] **`allowed_zones`/`blocked_zones` resources are not importable** — neither implements `ImportState` (singular variants do). Implement or document the limitation.
- [ ] **Fix misleading validator test** — `internal/provider/validators/stig_engine_test.go:493-499` seeds `zone_transfer_allowed_networks`/`notify_addresses`, but bindings read `allow_transfer`/`notify`, so the DNS-REQ-004/016 null paths aren't actually exercised (test passes via the dnssec attrs).
- [ ] **Direct unit tests for `TFConfigAdapter.IsNull`/`IsUnknown`** — `internal/provider/validators/accessors.go:101-133`. A typo'd attribute path is silently treated as unknown (passes validation); currently only covered indirectly.

## 4. Repo housekeeping (post-fork)

- [x] **Rename Go module path** to `github.com/bartei/terraform-provider-technitium` — go.mod, all imports, provider Address, GNUmakefile install path, README, docs/templates/examples. Build + tests verified.
- [x] **CONTRIBUTING.md / CODE_OF_CONDUCT / issue templates / SECURITY.md** — removed entirely.
- [x] **Update CLAUDE.md** — commands and conventions now match the lean CI.
- [x] **`.golangci.yml` + `make lint`** — kept as local-only tooling (not a CI gate).
- [x] **`renovate.json`** — dropped (automerge workflow gone; no dependabot config existed).
- [x] **`GPG_PRIVATE_KEY` secret** configured in repo settings (key has no passphrase; passphrase input dropped from release.yml).
- [x] **Commit & push** to `origin` (`bartei`), `main` tracking set.

## Done this session (for context)

- [x] Devcontainer (`.devcontainer/`) — Debian trixie, privileged, host network, DinD (iptables-nft fix for NixOS hosts), Go 1.26 / Terraform / golangci-lint 2.11.4 / Claude Code (native installer).
- [x] `CLAUDE.md` created.
- [x] CI workflows replaced with the `terraform-provider-nixos` style (`test.yml`, `release.yml`).
- [x] `TF_ACC` skip guard in `testAccDirectClient` — offline `go test ./...` now passes unfiltered.
- [x] `gofmt -w` across 11 files.
- [x] Remotes: `origin` → `bartei/...`, `upstream` → `darkhonor/...` (nothing pushed yet).
