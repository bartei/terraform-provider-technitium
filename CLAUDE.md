# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Terraform provider (plugin-framework, not SDKv2) for Technitium DNS Server, with embedded DISA STIG compliance validation (28 DNS security requirements, BIND 9.x V3R2 + Windows 2022 DNS V2R4) and NIST SP 800-53 Rev. 5 traceability. Module path is `github.com/bartei/terraform-provider-technitium`; requires Go 1.26.x.

## Development environment

The host may not have Go installed — use the devcontainer (`.devcontainer/devcontainer.json`, Debian trixie, privileged, host network, docker-in-docker). Inside it, all `make` targets work, including the docker-compose acceptance stacks.

## Commands

```bash
make build          # go build ./...
make test           # offline unit tests (go test ./... -count=1)
make lint           # golangci-lint v2 (local-only tool, not a CI gate; config in .golangci.yml)
make generate       # regenerate docs/ via tfplugindocs after schema/template/example changes
make build-fips     # GOEXPERIMENT=boringcrypto build
make generate-stig  # regenerate internal/provider/validators/stig_baselines_gen.go from tools/generate_stig_baselines.go
```

Run a single test: `go test ./internal/provider/validators/ -run 'TestName' -v -count=1`

### Acceptance tests (need Docker)

```bash
make testacc-up / testacc-down          # HTTP mode: compose up Technitium, bootstrap API token, run TF_ACC=1 suite
make testacc-up-tls / testacc-down-tls  # HTTPS mode: also generates TLS fixtures (tools/gen_test_tls); required for NSS/STIG-strict test families
```

Acceptance tests are gated on `TF_ACC` plus `TECHNITIUM_SERVER_URL`/`TECHNITIUM_API_TOKEN` env vars. `.env.test` (from `.env.test.example`) feeds them; only `TECHNITIUM_*` keys are exported into the test env — the admin password is piped to `scripts/test-token-bootstrap.sh` on stdin by design (never argv/env; issue #35). The test container runs as the host UID (issue #36); if `.testdata/` has stale root-owned files, the Makefile preflight fails with remediation instructions.

## Architecture

Three layers, strictly ordered: resource/data-source schema code → validation engines → HTTP client.

- `internal/client/` — thin Technitium HTTP API client. All API responses arrive in the `APIResponse` envelope (`status` + `response` raw JSON); non-"ok" statuses become `APIError`. TLS setup (custom CA file/dir, min version, server name) lives in `client.go`; `tls_errors.go` rewrites raw TLS failures into actionable diagnostics.
- `internal/provider/` — one file per resource/data-source (e.g. `zone_resource.go`, `record_resource.go`). New resources/data sources must be registered in `provider.go` (`Resources()` / `DataSources()`).
- `internal/provider/validators/` — the STIG compliance engine. Declarative `ValidatorBinding` tables in `stig.go` map DNS-REQ requirement IDs to resource attributes and validator funcs (stateless = config-only, stateful = needs provider data). `stig_baselines_gen.go` is GENERATED — edit `tools/generate_stig_baselines.go` and run `make generate-stig` instead.
- `internal/provider/inputvalidation/` — client-side DNS record format validation (separate engine, intentionally decoupled from the STIG engine; rule registry pattern, `ConfigAccessor` abstraction over Terraform config).
- `internal/provider/tfpath/` — path-string helpers shared by both validation engines.

Provider-level config (`stig_compliance` block: `enabled`, `enforcement` = warn/strict, NSS mode) determines whether STIG findings are warnings or plan-blocking errors. TLS provider attributes fall back to `TECHNITIUM_*` env vars (precedence: HCL > env > empty).

## Conventions

- Conventional Commits (`feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `security`), scope encouraged.
- NEVER add `Co-Authored-By`, "Generated with", or any AI-attribution lines to commits, tags, or PRs.
- Every file starts with the MPL-2.0 SPDX header.
- `docs/` is generated — never hand-edit; change `templates/` + schema and run `make generate`.
- Changes touching DNS config that validators evaluate should consider whether a DNS-REQ validator needs adding/extending; new validators need tests in `internal/provider/validators/`.
- CI (`.github/workflows/test.yml`): build, `go test -v ./...` (offline — acceptance tests skip without `TF_ACC`), gofmt, go vet, docs presence. Release (`release.yml`): GoReleaser + GPG signing on `v*` tags.
