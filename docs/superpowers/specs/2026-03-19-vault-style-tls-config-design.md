# Vault-Style TLS Configuration Design

**Date:** 2026-03-19
**Vikunja:** HomeLab #24
**Red Team Finding:** TPT-VULN-001 (compensating control)
**Status:** Approved

## Overview

Add full TLS configuration to the Technitium provider following the HashiCorp Vault provider's "platinum standard" nomenclature. Currently only `skip_tls_verify` exists. This feature supports the full spectrum from HomeLab users on plain HTTP to NSS-classified environments requiring TLS 1.3 with DoD CA chains.

No client certificate (mTLS) support — Technitium API does not support TLS client authentication.

## Decisions Made

| Decision | Choice | Rationale |
|---|---|---|
| `ca_cert_file` + `ca_cert_dir` | Both | DoD environments have multiple PKI trees (internal, external, DoD chains) |
| File paths vs inline PEM | File paths only | Certs managed on filesystem by PKI team; keeps PEM out of Terraform state |
| `tls_min_version` | Yes, default `"1.3"` always | Tiered enforcement across STIG/NSS contexts |
| Client constructor | `ClientConfig` struct | Scales cleanly, single source of truth |
| TLS connectivity probe | `Ping()` with TLS error classification at configure time, HTTPS only | Fail fast with actionable diagnostics; single handshake, no double-connect |
| HTTP URLs | TLS config ignored; STIG/NSS diagnostics still fire | Technitium default install is HTTP behind reverse proxy |
| Env var for `skip_tls_verify` | Yes — `TECHNITIUM_SKIP_TLS_VERIFY` | Vault-parity env var coverage |
| STIG validator integration | Unified engine | All TLS checks respect enforcement mode and suppressions |
| HCL vs env var precedence | HCL wins, env var is fallback | Standard Terraform provider convention (Vault, AWS) |

## Provider Schema

Four new `Optional` string attributes on `TechnitiumProviderModel`:

| Attribute | Description | Env Var | Default |
|---|---|---|---|
| `ca_cert_file` | Path to PEM-encoded CA certificate file | `TECHNITIUM_CACERT` | none |
| `ca_cert_dir` | Path to directory of PEM-encoded CA certificate files | `TECHNITIUM_CAPATH` | none |
| `tls_server_name` | SNI hostname override for TLS connections | `TECHNITIUM_TLS_SERVER_NAME` | none |
| `tls_min_version` | Minimum TLS version: `"1.2"` or `"1.3"` | `TECHNITIUM_TLS_MIN_VERSION` | `"1.3"` |

> **Note:** The `"1.3"` default is intentionally strict. If the Technitium server does not support TLS 1.3 (depends on .NET runtime and OS), the provider will produce an actionable error guiding the user to set `tls_min_version = "1.2"` (or `skip_tls_verify = true` for non-STIG environments). See "TLS Handshake Detection & Tiered Diagnostics" for the full error matrix.

Existing attribute gains env var:

| Attribute | Env Var (new) |
|---|---|
| `skip_tls_verify` | `TECHNITIUM_SKIP_TLS_VERIFY` |

**Precedence:** HCL attribute > environment variable > default value.

**Env var parsing:**
- String attributes: used as-is from `os.Getenv`.
- `skip_tls_verify` (`TECHNITIUM_SKIP_TLS_VERIFY`): parsed via `strconv.ParseBool` — accepts `"1"`, `"t"`, `"true"`, `"TRUE"`, `"0"`, `"f"`, `"false"`, `"FALSE"`, etc. Invalid values produce a configure-time error.
- `tls_min_version` (`TECHNITIUM_TLS_MIN_VERSION`): validated at configure time — must be `"1.2"` or `"1.3"`. Invalid values produce a configure-time error. (The `stringvalidator.OneOf` plan-time validator only fires on HCL values; env var values bypass schema validation and must be checked in `Configure()`.)

All TLS attributes are silently ignored when `server_url` begins with `http://`.

## Client Constructor

Replace `NewClient(baseURL, token string, skipTLSVerify bool)` with `NewClient(cfg ClientConfig)`.

```go
type ClientConfig struct {
    BaseURL        string
    Token          string
    SkipTLSVerify  bool     // default: false (explicit)
    CACertFile     string
    CACertDir      string
    TLSServerName  string
    TLSMinVersion  string   // default: "1.3"
}
```

### TLS Setup Logic (HTTPS only)

1. If `server_url` starts with `http://` — return plain `http.Client`, skip all TLS config.
2. Apply explicit defaults: `SkipTLSVerify = false`, `TLSMinVersion = "1.3"`.
3. Build `tls.Config`:
   - Load `CACertFile` into `x509.CertPool` as `RootCAs` (if set).
   - Load `CACertDir` into same `RootCAs` pool (if set) — see "CA Directory Behavior" below.
   - Set `ServerName` for SNI override (if set).
   - Set `MinVersion` — `tls.VersionTLS13` or `tls.VersionTLS12`.
   - Set `InsecureSkipVerify` if `SkipTLSVerify` is true.
4. Attach `tls.Config` to `http.Transport` on the `http.Client`.
5. **Connectivity probe** via `Ping()` (lightweight API call using the configured client).
   - Success: proceed normally.
   - TLS error: classify the error (version mismatch, unknown authority, wrong chain) and return a structured error for `Configure()` to build tiered diagnostics.
   - Non-TLS error (network unreachable, DNS failure): pass through unmodified.

> **Design note:** The probe uses the same `http.Client` and `tls.Config` as all subsequent API calls — no separate `tls.Dial`. This eliminates double-handshake overhead and guarantees config parity between the probe and real requests. The `http.Client.Timeout` (30s) governs the probe; no separate dial timeout is needed.

### CA Directory Behavior

`CACertDir` loading follows the `hashicorp/go-rootcerts` convention (Vault parity):
- **Non-recursive**: reads only the top-level directory, does not descend into subdirectories.
- **File filtering**: attempts to parse every file as PEM. No extension filtering (`.pem`, `.crt`, `.cer` all work).
- **Error handling**: files that fail to parse are skipped silently. Only errors if the directory itself is missing or no valid PEM files are found.
- **Symlinks**: followed (standard `os.ReadDir` behavior).

> **Implementation option:** Consider using `hashicorp/go-rootcerts` directly for Vault parity and to avoid reimplementing directory traversal. If adopted, add to `go.mod`.

## TLS Handshake Detection & Tiered Diagnostics

At configure time, after building the client, if `server_url` is HTTPS, a `Ping()` call probes the server. TLS errors from the underlying handshake are classified and `Configure()` returns context-appropriate diagnostics.

### HTTPS: TLS Version Mismatch (server doesn't support 1.3)

| Context | Level | Options Offered |
|---|---|---|
| No STIG | Error | `tls_min_version = "1.2"`, `skip_tls_verify = true` |
| STIG, non-NSS | Error | `tls_min_version = "1.2"` only |
| STIG, NSS | Error | Upgrade server only, no fallback |

### HTTPS: Certificate Verification Failed (unknown authority, no CA configured)

| Context | Level | Options Offered |
|---|---|---|
| No STIG | Error | `ca_cert_file`/`ca_cert_dir`, or `skip_tls_verify = true` |
| STIG, non-NSS | Error | `ca_cert_file`/`ca_cert_dir` only |
| STIG, NSS | Error | `ca_cert_file`/`ca_cert_dir` only |

### HTTPS: Certificate Verification Failed (CA configured but wrong chain)

| Context | Level | Options Offered |
|---|---|---|
| No STIG | Error | Verify correct CA chain, or `skip_tls_verify = true` |
| STIG, non-NSS | Error | Verify correct CA chain only |
| STIG, NSS | Error | Verify correct CA chain only |

### HTTPS: `skip_tls_verify = true` with CA certs configured

| Context | Level | Behavior |
|---|---|---|
| No STIG | Silent | `skip_tls_verify` wins, certs loaded but unused |
| STIG, non-NSS | Warning (via engine) | SC-8 violation warning |
| STIG, NSS | Error (via engine) | NSS requires verified transport |

### HTTP URL

| Context | Level | Diagnostic |
|---|---|---|
| No STIG | Silent | No diagnostic |
| STIG, non-NSS | Warning | Unencrypted transport violates SC-8 |
| STIG, NSS | Error | SC-8 requires encrypted transport |

### Non-TLS Failures

Network unreachable, DNS resolution failures, and other non-TLS errors pass through unmodified — no TLS-specific messaging applied.

## STIG Validator Integration

Move all TLS compliance checks into the unified validator/engine system. Remove the existing hardcoded SC-8 warning from `Configure()`.

### Engine Extension: Provider-Level Validation

The current engine supports resource-level validation via `TargetResource` keys (zone, server_settings, record, tsig_key). Provider-level TLS validators require:

1. **New target constant:** `TargetProvider` in the `TargetResource` enum.
2. **New accessor:** `ProviderConfigAccessor` interface (or reuse `ConfigAccessor` with provider attribute paths like `"skip_tls_verify"`, `"tls_min_version"`, `"server_url"`).
3. **New engine method:** `ValidateProvider(accessor ProviderConfigAccessor, findings *[]Finding)` — called from `Configure()`, routes through the same `emitFinding` logic as resource validators.
4. **Binding registration:** Provider-level validators registered under `TargetProvider` in the bindings map.

This ensures provider-level validators fire during `Configure()` (not deferred to resource-level `ConfigValidators` or `ModifyPlan`), while sharing enforcement mode, suppression, and diagnostic formatting with all existing validators.

### New Validators

| Validator | Requirement | Trigger | Non-NSS STIG | NSS |
|---|---|---|---|---|
| `validateTLSEnabled` | SC-8 | `server_url` is `http://` | Warning | Error |
| `validateTLSMinVersion` | SC-8 | `tls_min_version = "1.2"` | Warning | Error |
| `validateTLSVerification` | SC-8 | `skip_tls_verify = true` | Warning | Error |

> **Enforcement behavior:** "Warning" and "Error" in the table above reflect the *effective* behavior, not a fixed severity. The validators emit findings through the engine, which applies enforcement mode: `strict` mode escalates warnings to errors, `silent` mode suppresses them, `warn` mode (default for non-NSS) emits warnings. NSS always enforces strict regardless of the configured mode.

All validators:
- Respect `enforcement` mode (strict/warn/silent)
- Support per-requirement suppression
- Produce diagnostics with RMF traceability (STIG rule, CCI, NIST control)
- Evaluate as provider-level validators during `Configure()` via `ValidateProvider()`, not deferred to resource lifecycle

## Error Handling & Edge Cases

| Scenario | Behavior |
|---|---|
| `ca_cert_file` path doesn't exist | Error: "CA certificate file not found: `<path>`" |
| `ca_cert_dir` path doesn't exist | Error: "CA certificate directory not found: `<path>`" |
| `ca_cert_dir` contains no valid PEM files | Error: "No valid PEM certificates found in `<path>`" |
| `ca_cert_file` contains invalid PEM | Error: "Failed to parse CA certificate: `<path>`" |
| Both `ca_cert_file` and `ca_cert_dir` set | Valid — both loaded into same `RootCAs` pool |
| `tls_min_version` invalid value | Plan-time error via `stringvalidator.OneOf("1.2", "1.3")` |
| TLS attributes set with `http://` URL | Silently ignored |
| `skip_tls_verify = true` with CA certs | `skip_tls_verify` wins (matches Go behavior) |
| `tls_server_name` with `skip_tls_verify = true` | SNI still sent (ClientHello field, independent of verification) |

## Testing Strategy

| Test Type | Coverage |
|---|---|
| Unit: ClientConfig defaults | `TLSMinVersion` defaults to `"1.3"`, `SkipTLSVerify` defaults to `false` (explicit) |
| Unit: CA cert loading | Valid PEM file, valid PEM dir, missing file, missing dir, empty dir, invalid PEM, both file + dir combined |
| Unit: TLS config construction | HTTPS gets full `tls.Config`, HTTP gets plain transport. SNI set when configured. MinVersion maps correctly |
| Unit: Handshake error detection | Version mismatch, unknown authority (no CA), wrong CA chain, network errors pass through |
| Unit: Tiered diagnostics | Each error scenario x 3 STIG contexts (none, non-NSS, NSS) — correct message, correct options |
| Unit: STIG validators | `validateTLSEnabled`, `validateTLSMinVersion`, `validateTLSVerification` — enforcement modes + suppression |
| Unit: Env var fallbacks | All 5 env vars resolve correctly; HCL takes precedence over env var; default applies when neither set; invalid bool/version env vars produce errors |
| Acceptance: Provider configure | If Docker test instance supports TLS, validate full flow; otherwise unit coverage is sufficient |

## Files Changed

| File | Change |
|---|---|
| `internal/provider/provider.go` | Add 4 schema attrs, env var fallbacks, build `ClientConfig`, updated `Configure()` diagnostics |
| `internal/client/client.go` | `ClientConfig` struct, new `NewClient(cfg)`, TLS setup, `tls.Dial` probe, error classification |
| `internal/provider/validators/stig.go` | Add 3 new provider-level validator bindings |
| `internal/provider/validators/stig_baselines_gen.go` | Add/update SC-8 requirement entries if needed |
| `internal/provider/validators/stig_engine.go` | Add `TargetProvider`, `ProviderConfigAccessor`, `ValidateProvider()` method |
| `internal/client/client_test.go` | Unit tests for ClientConfig, CA loading, TLS config, error detection |
| `internal/provider/provider_test.go` | Unit tests for env var precedence, tiered diagnostics |
| `internal/provider/validators/stig_test.go` | Unit tests for 3 new validators |
| `go.mod` / `go.sum` | Add `hashicorp/go-rootcerts` if adopted for CA directory loading |

## Env Var Summary

| Attribute | Env Var | Status |
|---|---|---|
| `server_url` | `TECHNITIUM_SERVER_URL` | Existing |
| `api_token` | `TECHNITIUM_API_TOKEN` | Existing |
| `skip_tls_verify` | `TECHNITIUM_SKIP_TLS_VERIFY` | New |
| `ca_cert_file` | `TECHNITIUM_CACERT` | New |
| `ca_cert_dir` | `TECHNITIUM_CAPATH` | New |
| `tls_server_name` | `TECHNITIUM_TLS_SERVER_NAME` | New |
| `tls_min_version` | `TECHNITIUM_TLS_MIN_VERSION` | New |
