# Vault-Style TLS Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Vault-parity TLS configuration to the Technitium provider with tiered STIG/NSS enforcement and context-aware diagnostics.

**Architecture:** Replace the 3-arg `NewClient` with a `ClientConfig` struct. Build `tls.Config` from CA cert files/dirs, SNI override, and min version. Probe connectivity via `Ping()` at configure time. Classify TLS errors and emit tiered diagnostics based on STIG/NSS context. Extend the STIG engine with `TargetProvider` for provider-level validators.

**Tech Stack:** Go stdlib `crypto/tls`, `crypto/x509`, `os`, `strconv`. Optional: `hashicorp/go-rootcerts`. Terraform Plugin Framework v1.19.0, existing STIG engine.

**Spec:** `docs/superpowers/specs/2026-03-19-vault-style-tls-config-design.md`

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/client/client.go` | `ClientConfig` struct, refactored `NewClient(cfg)`, TLS config construction, CA loading, `Ping()`-based probe |
| `internal/client/tls_errors.go` | TLS error classification (`ClassifyTLSError`), error types for version mismatch / unknown authority / wrong chain |
| `internal/client/client_test.go` | Unit tests for `ClientConfig` defaults, `NewClient` refactor, CA loading, TLS config |
| `internal/client/tls_errors_test.go` | Unit tests for TLS error classification |
| `internal/provider/provider.go` | 4 new schema attrs, env var fallbacks with precedence, `ClientConfig` construction, tiered diagnostics in `Configure()` |
| `internal/provider/provider_test.go` | Unit tests for env var precedence, tiered diagnostic message generation |
| `internal/provider/validators/stig_engine.go` | `ValidateProvider()` method (thin wrapper delegating to `ValidateConfig` with `TargetProvider`) |
| `internal/provider/validators/stig.go` | `ProviderBindings` array with 3 new validators, validator functions |
| `internal/provider/validators/stig_baselines_gen.go` | Add `TargetProvider` constant, add DNS-REQ-028 requirement for TLS transport (SC-8) |
| `internal/provider/validators/stig_engine_test.go` | Unit tests for `ValidateProvider()` |
| `internal/provider/validators/stig_test.go` | Update structural tests to include `ProviderBindings` |
| `internal/provider/stig_acceptance_test.go` | Acceptance tests for TLS STIG validators |

---

## Task 1: Refactor NewClient to ClientConfig Struct

**Files:**
- Modify: `internal/client/client.go:47-72`
- Modify: `internal/client/client_test.go`
- Modify: `internal/provider/provider.go:183-200` (caller)

This task changes the constructor signature only. No new TLS features yet. All existing tests must continue to pass.

- [ ] **Step 1: Update ClientConfig struct and NewClient signature**

In `internal/client/client.go`, replace the current `NewClient` function:

```go
// ClientConfig holds all configuration for the Technitium API client.
type ClientConfig struct {
	BaseURL       string
	Token         string
	SkipTLSVerify bool   // default: false
	CACertFile    string
	CACertDir     string
	TLSServerName string
	TLSMinVersion string // "1.2" or "1.3", default: "1.3"
}

// NewClient creates a new Technitium API client.
func NewClient(cfg ClientConfig) (*Client, error) {
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("server_url must not be empty")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("api_token must not be empty")
	}

	// Apply defaults
	if cfg.TLSMinVersion == "" {
		cfg.TLSMinVersion = "1.3"
	}

	transport := &http.Transport{}
	if cfg.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // User explicitly opted in via skip_tls_verify
		}
	}

	return &Client{
		baseURL: cfg.BaseURL,
		token:   cfg.Token,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}, nil
}
```

- [ ] **Step 2: Update all existing client tests**

In `internal/client/client_test.go`, update every `NewClient` call to use `ClientConfig`. Example for `TestNewClient_ValidInputs`:

```go
func TestNewClient_ValidInputs(t *testing.T) {
	c, err := NewClient(ClientConfig{
		BaseURL: "https://dns.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}
```

Update all 14 existing tests similarly. For `TestNewClient_SkipTLSVerify`:

```go
func TestNewClient_SkipTLSVerify(t *testing.T) {
	c, err := NewClient(ClientConfig{
		BaseURL:       "https://dns.example.com",
		Token:         "test-token",
		SkipTLSVerify: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
}
```

- [ ] **Step 3: Add test for TLSMinVersion default**

```go
func TestNewClient_TLSMinVersionDefault(t *testing.T) {
	// ClientConfig with no TLSMinVersion should default to "1.3"
	cfg := ClientConfig{
		BaseURL: "https://dns.example.com",
		Token:   "test-token",
	}
	_, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The default is applied internally; we verify via TLS config in later tasks
}
```

- [ ] **Step 4: Update provider.go caller**

In `internal/provider/provider.go`, update the `Configure()` method where `NewClient` is called (around line 189):

```go
apiClient, err := client.NewClient(client.ClientConfig{
	BaseURL:       serverURL,
	Token:         apiToken,
	SkipTLSVerify: skipTLSVerify,
})
```

- [ ] **Step 5: Run all tests**

Run: `go test ./internal/client/... ./internal/provider/... -v -count=1`
Expected: All existing tests pass. No behavior change.

- [ ] **Step 6: Commit**

```bash
git add internal/client/client.go internal/client/client_test.go internal/provider/provider.go
git commit -m "refactor(client): replace NewClient positional args with ClientConfig struct

Preparation for Vault-style TLS configuration. No behavior change —
all existing tests pass with the new signature."
```

---

## Task 2: TLS Error Classification

**Files:**
- Create: `internal/client/tls_errors.go`
- Create: `internal/client/tls_errors_test.go`

Build the error classification layer before the TLS config construction. This is a pure function with no dependencies on the client.

- [ ] **Step 1: Write failing tests for TLS error classification**

Create `internal/client/tls_errors_test.go`:

```go
package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestClassifyTLSError_VersionMismatch(t *testing.T) {
	// tls.RecordHeaderError indicates protocol version mismatch
	err := tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}
	result := ClassifyTLSError(err)
	if result.Kind != TLSErrVersionMismatch {
		t.Errorf("expected TLSErrVersionMismatch, got %v", result.Kind)
	}
}

func TestClassifyTLSError_UnknownAuthority(t *testing.T) {
	err := x509.UnknownAuthorityError{}
	result := ClassifyTLSError(err)
	if result.Kind != TLSErrUnknownAuthority {
		t.Errorf("expected TLSErrUnknownAuthority, got %v", result.Kind)
	}
}

func TestClassifyTLSError_CertificateInvalid(t *testing.T) {
	err := x509.CertificateInvalidError{Reason: x509.Expired}
	result := ClassifyTLSError(err)
	if result.Kind != TLSErrCertificateInvalid {
		t.Errorf("expected TLSErrCertificateInvalid, got %v", result.Kind)
	}
}

func TestClassifyTLSError_HostnameMismatch(t *testing.T) {
	err := x509.HostnameError{Host: "dns.example.com"}
	result := ClassifyTLSError(err)
	if result.Kind != TLSErrHostnameMismatch {
		t.Errorf("expected TLSErrHostnameMismatch, got %v", result.Kind)
	}
}

func TestClassifyTLSError_NetworkError(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	result := ClassifyTLSError(err)
	if result.Kind != TLSErrNotTLS {
		t.Errorf("expected TLSErrNotTLS, got %v", result.Kind)
	}
}

func TestClassifyTLSError_WrappedError(t *testing.T) {
	// Errors from http.Client are often wrapped
	inner := x509.UnknownAuthorityError{}
	wrapped := fmt.Errorf("Get https://dns.example.com: %w", inner)
	result := ClassifyTLSError(wrapped)
	if result.Kind != TLSErrUnknownAuthority {
		t.Errorf("expected TLSErrUnknownAuthority through wrapped error, got %v", result.Kind)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/client/... -run TestClassifyTLSError -v`
Expected: FAIL — `ClassifyTLSError` undefined

- [ ] **Step 3: Implement TLS error classification**

Create `internal/client/tls_errors.go`:

```go
package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
)

// TLSErrorKind categorizes TLS connection failures for tiered diagnostics.
type TLSErrorKind int

const (
	// TLSErrNotTLS indicates the error is not TLS-related (network, DNS, etc).
	TLSErrNotTLS TLSErrorKind = iota
	// TLSErrVersionMismatch indicates the server doesn't support the requested TLS version.
	TLSErrVersionMismatch
	// TLSErrUnknownAuthority indicates the server cert was signed by an unknown CA.
	TLSErrUnknownAuthority
	// TLSErrCertificateInvalid indicates the server cert is invalid (expired, wrong usage, etc).
	TLSErrCertificateInvalid
	// TLSErrHostnameMismatch indicates the server cert doesn't match the requested hostname.
	TLSErrHostnameMismatch
)

// TLSError holds a classified TLS error with the original error preserved.
type TLSError struct {
	Kind     TLSErrorKind
	Original error
}

// ClassifyTLSError examines an error from an HTTP request or TLS handshake
// and returns a classified TLSError. Non-TLS errors return TLSErrNotTLS.
func ClassifyTLSError(err error) TLSError {
	if err == nil {
		return TLSError{Kind: TLSErrNotTLS}
	}

	// Check for x509 certificate errors (most specific first)
	var unknownAuthErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthErr) {
		return TLSError{Kind: TLSErrUnknownAuthority, Original: err}
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return TLSError{Kind: TLSErrHostnameMismatch, Original: err}
	}

	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return TLSError{Kind: TLSErrCertificateInvalid, Original: err}
	}

	// Check for TLS record header error (version mismatch)
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return TLSError{Kind: TLSErrVersionMismatch, Original: err}
	}

	// Check for TLS version error messages in string form
	// (some Go versions wrap these differently)
	errMsg := err.Error()
	if strings.Contains(errMsg, "protocol version not supported") ||
		strings.Contains(errMsg, "no mutual version") {
		return TLSError{Kind: TLSErrVersionMismatch, Original: err}
	}

	// Not a TLS-specific error
	return TLSError{Kind: TLSErrNotTLS, Original: err}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/client/... -run TestClassifyTLSError -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/client/tls_errors.go internal/client/tls_errors_test.go
git commit -m "feat(client): add TLS error classification for tiered diagnostics

ClassifyTLSError categorizes TLS handshake failures into version mismatch,
unknown authority, certificate invalid, and hostname mismatch. Supports
wrapped errors via errors.As. Non-TLS errors pass through as TLSErrNotTLS."
```

---

## Task 3: CA Certificate Loading

**Files:**
- Modify: `internal/client/client.go`
- Modify: `internal/client/client_test.go`

Add CA cert file and directory loading to `NewClient`. TDD — tests first.

- [ ] **Step 1: Write failing tests for CA cert loading**

Add to `internal/client/client_test.go`:

```go
func TestNewClient_CACertFile_Valid(t *testing.T) {
	// Create a temp PEM file with a self-signed CA cert
	certPEM := generateTestCACert(t)
	certFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(ClientConfig{
		BaseURL:    "https://dns.example.com",
		Token:      "test-token",
		CACertFile: certFile,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected custom RootCAs to be set")
	}
}

func TestNewClient_CACertFile_NotFound(t *testing.T) {
	_, err := NewClient(ClientConfig{
		BaseURL:    "https://dns.example.com",
		Token:      "test-token",
		CACertFile: "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Fatal("expected error for missing cert file")
	}
	if !strings.Contains(err.Error(), "CA certificate file not found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewClient_CACertFile_InvalidPEM(t *testing.T) {
	certFile := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(certFile, []byte("not a PEM file"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := NewClient(ClientConfig{
		BaseURL:    "https://dns.example.com",
		Token:      "test-token",
		CACertFile: certFile,
	})
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
	if !strings.Contains(err.Error(), "failed to parse CA certificate") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewClient_CACertDir_Valid(t *testing.T) {
	certPEM := generateTestCACert(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca1.pem"), certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(ClientConfig{
		BaseURL:   "https://dns.example.com",
		Token:     "test-token",
		CACertDir: dir,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected custom RootCAs to be set")
	}
}

func TestNewClient_CACertDir_NotFound(t *testing.T) {
	_, err := NewClient(ClientConfig{
		BaseURL:   "https://dns.example.com",
		Token:     "test-token",
		CACertDir: "/nonexistent/certs",
	})
	if err == nil {
		t.Fatal("expected error for missing cert dir")
	}
	if !strings.Contains(err.Error(), "CA certificate directory not found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewClient_CACertDir_Empty(t *testing.T) {
	dir := t.TempDir()
	_, err := NewClient(ClientConfig{
		BaseURL:   "https://dns.example.com",
		Token:     "test-token",
		CACertDir: dir,
	})
	if err == nil {
		t.Fatal("expected error for empty cert dir")
	}
	if !strings.Contains(err.Error(), "no valid PEM certificates found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewClient_CACertDir_SkipsInvalidFiles(t *testing.T) {
	certPEM := generateTestCACert(t)
	dir := t.TempDir()
	// One valid, one invalid
	os.WriteFile(filepath.Join(dir, "valid.pem"), certPEM, 0644)
	os.WriteFile(filepath.Join(dir, "invalid.txt"), []byte("not pem"), 0644)

	c, err := NewClient(ClientConfig{
		BaseURL:   "https://dns.example.com",
		Token:     "test-token",
		CACertDir: dir,
	})
	if err != nil {
		t.Fatalf("should succeed with at least one valid cert: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected custom RootCAs to be set")
	}
}

func TestNewClient_CACertFileAndDir_Combined(t *testing.T) {
	certPEM := generateTestCACert(t)
	certFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(certFile, certPEM, 0644)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ca2.pem"), certPEM, 0644)

	c, err := NewClient(ClientConfig{
		BaseURL:    "https://dns.example.com",
		Token:      "test-token",
		CACertFile: certFile,
		CACertDir:  dir,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected custom RootCAs from both file and dir")
	}
}

func TestNewClient_HTTP_IgnoresTLSConfig(t *testing.T) {
	c, err := NewClient(ClientConfig{
		BaseURL:    "http://dns.example.com",
		Token:      "test-token",
		CACertFile: "/nonexistent/ca.pem", // would error on HTTPS
		CACertDir:  "/nonexistent/certs",
	})
	if err != nil {
		t.Fatalf("HTTP should ignore TLS config: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig != nil {
		t.Error("HTTP URL should not have TLS config")
	}
}
```

Add test helper at top of test file:

```go
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func generateTestCACert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/client/... -run "TestNewClient_CACert|TestNewClient_HTTP_Ignores" -v`
Expected: FAIL — new tests fail because `NewClient` doesn't handle CA certs yet

- [ ] **Step 3: Implement CA cert loading in NewClient**

Update `NewClient` in `internal/client/client.go`. Add imports for `crypto/x509`, `encoding/pem`, `os`, `path/filepath`. Replace the transport/TLS section:

```go
func NewClient(cfg ClientConfig) (*Client, error) {
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("server_url must not be empty")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("api_token must not be empty")
	}

	if cfg.TLSMinVersion == "" {
		cfg.TLSMinVersion = "1.3"
	}

	transport := &http.Transport{}
	isHTTPS := strings.HasPrefix(cfg.BaseURL, "https://")

	if isHTTPS {
		tlsConfig := &tls.Config{} //nolint:gosec // MinVersion set below

		// Load CA certificates
		rootCAs, err := loadCACerts(cfg.CACertFile, cfg.CACertDir)
		if err != nil {
			return nil, err
		}
		if rootCAs != nil {
			tlsConfig.RootCAs = rootCAs
		}

		// SNI override
		if cfg.TLSServerName != "" {
			tlsConfig.ServerName = cfg.TLSServerName
		}

		// Min TLS version
		switch cfg.TLSMinVersion {
		case "1.3":
			tlsConfig.MinVersion = tls.VersionTLS13
		case "1.2":
			tlsConfig.MinVersion = tls.VersionTLS12
		default:
			return nil, fmt.Errorf("invalid tls_min_version %q: must be \"1.2\" or \"1.3\"", cfg.TLSMinVersion)
		}

		// Skip TLS verify
		if cfg.SkipTLSVerify {
			tlsConfig.InsecureSkipVerify = true //nolint:gosec // User explicitly opted in via skip_tls_verify
		}

		transport.TLSClientConfig = tlsConfig
	}
	// HTTP: no TLS config, ignore all TLS attributes silently

	return &Client{
		baseURL: cfg.BaseURL,
		token:   cfg.Token,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}, nil
}

// loadCACerts builds an x509.CertPool from a cert file and/or cert directory.
// Returns nil pool if neither is configured.
func loadCACerts(certFile, certDir string) (*x509.CertPool, error) {
	if certFile == "" && certDir == "" {
		return nil, nil
	}

	pool := x509.NewCertPool()
	loaded := 0

	// Load single cert file
	if certFile != "" {
		data, err := os.ReadFile(certFile)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("CA certificate file not found: %s", certFile)
			}
			return nil, fmt.Errorf("failed to read CA certificate file: %w", err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("failed to parse CA certificate: %s", certFile)
		}
		loaded++
	}

	// Load cert directory (non-recursive, skip invalid files)
	if certDir != "" {
		entries, err := os.ReadDir(certDir)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("CA certificate directory not found: %s", certDir)
			}
			return nil, fmt.Errorf("failed to read CA certificate directory: %w", err)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(certDir, entry.Name()))
			if err != nil {
				continue // skip unreadable files
			}
			if pool.AppendCertsFromPEM(data) {
				loaded++
			}
			// skip files that don't parse as PEM (per Vault convention)
		}
	}

	if loaded == 0 && certDir != "" && certFile == "" {
		return nil, fmt.Errorf("no valid PEM certificates found in %s", certDir)
	}

	return pool, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/client/... -v -count=1`
Expected: ALL tests pass (existing + new)

- [ ] **Step 5: Commit**

```bash
git add internal/client/client.go internal/client/client_test.go
git commit -m "feat(client): add CA certificate file and directory loading

Loads PEM certificates from ca_cert_file and ca_cert_dir into a custom
RootCAs pool. Directory loading is non-recursive, skips invalid files
(Vault convention). HTTP URLs silently ignore all TLS configuration."
```

---

## Task 4: TLS Config Construction (SNI, MinVersion)

**Files:**
- Modify: `internal/client/client.go` (already done in Task 3 implementation)
- Modify: `internal/client/client_test.go`

The TLS config construction was implemented in Task 3. This task adds focused tests for SNI and MinVersion.

- [ ] **Step 1: Write tests for SNI and MinVersion**

Add to `internal/client/client_test.go`:

```go
func TestNewClient_TLSServerName(t *testing.T) {
	c, err := NewClient(ClientConfig{
		BaseURL:       "https://dns.example.com",
		Token:         "test-token",
		TLSServerName: "custom-sni.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig.ServerName != "custom-sni.example.com" {
		t.Errorf("expected SNI custom-sni.example.com, got %q", transport.TLSClientConfig.ServerName)
	}
}

func TestNewClient_TLSMinVersion13(t *testing.T) {
	c, err := NewClient(ClientConfig{
		BaseURL:       "https://dns.example.com",
		Token:         "test-token",
		TLSMinVersion: "1.3",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got %d", transport.TLSClientConfig.MinVersion)
	}
}

func TestNewClient_TLSMinVersion12(t *testing.T) {
	c, err := NewClient(ClientConfig{
		BaseURL:       "https://dns.example.com",
		Token:         "test-token",
		TLSMinVersion: "1.2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2, got %d", transport.TLSClientConfig.MinVersion)
	}
}

func TestNewClient_TLSMinVersionInvalid(t *testing.T) {
	_, err := NewClient(ClientConfig{
		BaseURL:       "https://dns.example.com",
		Token:         "test-token",
		TLSMinVersion: "1.1",
	})
	if err == nil {
		t.Fatal("expected error for invalid TLS version")
	}
	if !strings.Contains(err.Error(), "invalid tls_min_version") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewClient_TLSMinVersionDefault(t *testing.T) {
	c, err := NewClient(ClientConfig{
		BaseURL: "https://dns.example.com",
		Token:   "test-token",
		// TLSMinVersion not set — should default to 1.3
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("default should be TLS 1.3, got %d", transport.TLSClientConfig.MinVersion)
	}
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `go test ./internal/client/... -run "TestNewClient_TLS" -v`
Expected: All PASS (implementation was done in Task 3)

- [ ] **Step 3: Commit**

```bash
git add internal/client/client_test.go
git commit -m "test(client): add TLS SNI and MinVersion configuration tests

Verifies ServerName propagation, MinVersion 1.2/1.3 mapping,
invalid version rejection, and 1.3 default behavior."
```

---

## Task 5: Provider Schema and Env Var Fallbacks

**Files:**
- Modify: `internal/provider/provider.go:33-38` (model struct)
- Modify: `internal/provider/provider.go:86-153` (schema)
- Modify: `internal/provider/provider.go:155-200` (Configure env vars + client construction)
- Create: `internal/provider/provider_tls_test.go`

- [ ] **Step 1: Write failing tests for env var precedence**

Create `internal/provider/provider_tls_test.go`:

```go
package provider

import (
	"os"
	"testing"
)

func TestResolveTLSConfig_HCLWinsOverEnv(t *testing.T) {
	t.Setenv("TECHNITIUM_CACERT", "/env/ca.pem")

	result := resolveTLSString("hcl-value", "TECHNITIUM_CACERT")
	if result != "hcl-value" {
		t.Errorf("HCL should win over env var, got %q", result)
	}
}

func TestResolveTLSConfig_EnvFallback(t *testing.T) {
	t.Setenv("TECHNITIUM_CACERT", "/env/ca.pem")

	result := resolveTLSString("", "TECHNITIUM_CACERT")
	if result != "/env/ca.pem" {
		t.Errorf("env var should be fallback, got %q", result)
	}
}

func TestResolveTLSConfig_Default(t *testing.T) {
	// No env var set
	result := resolveTLSString("", "TECHNITIUM_CACERT")
	if result != "" {
		t.Errorf("should return empty when neither HCL nor env set, got %q", result)
	}
}

func TestResolveTLSBool_HCLWinsOverEnv(t *testing.T) {
	t.Setenv("TECHNITIUM_SKIP_TLS_VERIFY", "true")

	result, err := resolveTLSBool(ptrBool(false), "TECHNITIUM_SKIP_TLS_VERIFY", false)
	if err != nil {
		t.Fatal(err)
	}
	if result != false {
		t.Error("HCL false should win over env true")
	}
}

func TestResolveTLSBool_EnvFallback(t *testing.T) {
	t.Setenv("TECHNITIUM_SKIP_TLS_VERIFY", "true")

	result, err := resolveTLSBool(nil, "TECHNITIUM_SKIP_TLS_VERIFY", false)
	if err != nil {
		t.Fatal(err)
	}
	if result != true {
		t.Error("env var should be used as fallback")
	}
}

func TestResolveTLSBool_InvalidEnvVar(t *testing.T) {
	t.Setenv("TECHNITIUM_SKIP_TLS_VERIFY", "maybe")

	_, err := resolveTLSBool(nil, "TECHNITIUM_SKIP_TLS_VERIFY", false)
	if err == nil {
		t.Error("expected error for invalid bool env var")
	}
}

func TestResolveTLSBool_Default(t *testing.T) {
	result, err := resolveTLSBool(nil, "TECHNITIUM_SKIP_TLS_VERIFY", false)
	if err != nil {
		t.Fatal(err)
	}
	if result != false {
		t.Error("should return default when neither HCL nor env set")
	}
}

func TestResolveTLSMinVersion_EnvInvalid(t *testing.T) {
	t.Setenv("TECHNITIUM_TLS_MIN_VERSION", "1.1")

	_, err := resolveTLSMinVersion("", "TECHNITIUM_TLS_MIN_VERSION", "1.3")
	if err == nil {
		t.Error("expected error for invalid TLS min version from env")
	}
}

// Helper
func ptrBool(b bool) *bool { return &b }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/provider/... -run "TestResolveTLS" -v`
Expected: FAIL — functions not defined

- [ ] **Step 3: Add TLS attributes to provider model and schema**

In `internal/provider/provider.go`, update `TechnitiumProviderModel`:

```go
type TechnitiumProviderModel struct {
	ServerURL      types.String         `tfsdk:"server_url"`
	APIToken       types.String         `tfsdk:"api_token"`
	SkipTLSVerify  types.Bool           `tfsdk:"skip_tls_verify"`
	CACertFile     types.String         `tfsdk:"ca_cert_file"`
	CACertDir      types.String         `tfsdk:"ca_cert_dir"`
	TLSServerName  types.String         `tfsdk:"tls_server_name"`
	TLSMinVersion  types.String         `tfsdk:"tls_min_version"`
	STIGCompliance *STIGComplianceModel `tfsdk:"stig_compliance"`
}
```

Add 4 new attributes to `Schema()` after `skip_tls_verify`:

```go
"ca_cert_file": schema.StringAttribute{
	Description: "Path to a PEM-encoded CA certificate file to validate the Technitium server's TLS certificate. " +
		"May be set via the TECHNITIUM_CACERT environment variable.",
	Optional: true,
},
"ca_cert_dir": schema.StringAttribute{
	Description: "Path to a directory of PEM-encoded CA certificate files to validate the Technitium server's TLS certificate. " +
		"Files that fail to parse are skipped. May be set via the TECHNITIUM_CAPATH environment variable.",
	Optional: true,
},
"tls_server_name": schema.StringAttribute{
	Description: "Name to use as the SNI host when connecting to the Technitium server via TLS. " +
		"May be set via the TECHNITIUM_TLS_SERVER_NAME environment variable.",
	Optional: true,
},
"tls_min_version": schema.StringAttribute{
	Description: "Minimum TLS version to accept when connecting to the Technitium server. " +
		"Valid values: \"1.2\", \"1.3\". Defaults to \"1.3\". " +
		"May be set via the TECHNITIUM_TLS_MIN_VERSION environment variable.",
	Optional: true,
	Validators: []validator.String{
		stringvalidator.OneOf("1.2", "1.3"),
	},
},
```

- [ ] **Step 4: Implement resolver functions and update Configure()**

Add resolver functions to `internal/provider/provider.go`:

```go
// resolveTLSString resolves a TLS config string: HCL > env var > empty.
func resolveTLSString(hclValue, envVar string) string {
	if hclValue != "" {
		return hclValue
	}
	return os.Getenv(envVar)
}

// resolveTLSBool resolves a TLS config bool: HCL > env var > default.
// hclValue is nil when the HCL attribute was not set.
func resolveTLSBool(hclValue *bool, envVar string, defaultVal bool) (bool, error) {
	if hclValue != nil {
		return *hclValue, nil
	}
	envStr := os.Getenv(envVar)
	if envStr != "" {
		val, err := strconv.ParseBool(envStr)
		if err != nil {
			return false, fmt.Errorf("invalid value for %s: %q (expected true/false)", envVar, envStr)
		}
		return val, nil
	}
	return defaultVal, nil
}

// resolveTLSMinVersion resolves tls_min_version: HCL > env var > default.
// Validates the resolved value is "1.2" or "1.3".
func resolveTLSMinVersion(hclValue, envVar, defaultVal string) (string, error) {
	result := hclValue
	if result == "" {
		result = os.Getenv(envVar)
	}
	if result == "" {
		return defaultVal, nil
	}
	if result != "1.2" && result != "1.3" {
		return "", fmt.Errorf("invalid value for %s: %q (must be \"1.2\" or \"1.3\")", envVar, result)
	}
	return result, nil
}
```

Update `Configure()` to use resolvers and build `ClientConfig`:

```go
// Resolve TLS configuration (HCL > env var > default)
var skipTLSPtr *bool
if !config.SkipTLSVerify.IsNull() {
	v := config.SkipTLSVerify.ValueBool()
	skipTLSPtr = &v
}
skipTLSVerify, err := resolveTLSBool(skipTLSPtr, "TECHNITIUM_SKIP_TLS_VERIFY", false)
if err != nil {
	resp.Diagnostics.AddError("Invalid TLS configuration", err.Error())
	return
}

caCertFile := resolveTLSString(config.CACertFile.ValueString(), "TECHNITIUM_CACERT")
caCertDir := resolveTLSString(config.CACertDir.ValueString(), "TECHNITIUM_CAPATH")
tlsServerName := resolveTLSString(config.TLSServerName.ValueString(), "TECHNITIUM_TLS_SERVER_NAME")
tlsMinVersion, err := resolveTLSMinVersion(config.TLSMinVersion.ValueString(), "TECHNITIUM_TLS_MIN_VERSION", "1.3")
if err != nil {
	resp.Diagnostics.AddError("Invalid TLS configuration", err.Error())
	return
}

// Create API client
apiClient, err := client.NewClient(client.ClientConfig{
	BaseURL:       serverURL,
	Token:         apiToken,
	SkipTLSVerify: skipTLSVerify,
	CACertFile:    caCertFile,
	CACertDir:     caCertDir,
	TLSServerName: tlsServerName,
	TLSMinVersion: tlsMinVersion,
})
```

Add imports to provider.go:
- `"strconv"` for `ParseBool`
- `"strings"` (likely already present)
- `"github.com/hashicorp/terraform-plugin-framework/schema/validator"` for the `Validators` field
- `"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"` for `OneOf`

Verify `terraform-plugin-framework-validators` is in `go.mod` — it was added in the blocked/allowed zones feature. If not present, run `go get github.com/hashicorp/terraform-plugin-framework-validators`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/provider/... -run "TestResolveTLS" -v`
Expected: All PASS

Run: `go test ./internal/client/... ./internal/provider/... -v -count=1`
Expected: All PASS (full suite)

- [ ] **Step 6: Commit**

```bash
git add internal/provider/provider.go internal/provider/provider_tls_test.go
git commit -m "feat(provider): add TLS schema attributes and env var fallbacks

Adds ca_cert_file, ca_cert_dir, tls_server_name, tls_min_version to
provider schema. Env var fallbacks: TECHNITIUM_CACERT, TECHNITIUM_CAPATH,
TECHNITIUM_TLS_SERVER_NAME, TECHNITIUM_TLS_MIN_VERSION, TECHNITIUM_SKIP_TLS_VERIFY.
HCL takes precedence over env vars. Runtime validation for env var values."
```

---

## Task 6: Tiered Diagnostic Messages in Configure()

**Files:**
- Modify: `internal/provider/provider.go`
- Modify: `internal/provider/provider_tls_test.go`

Add the Ping()-based probe with TLS error classification and context-aware diagnostic messages.

- [ ] **Step 1: Write failing tests for tiered diagnostics**

Add to `internal/provider/provider_tls_test.go`:

```go
func TestBuildTLSDiagnostic_VersionMismatch_NoSTIG(t *testing.T) {
	msg := buildTLSDiagnostic(
		client.TLSError{Kind: client.TLSErrVersionMismatch},
		"https://dns.example.com",
		false, // stigEnabled
		false, // nss
	)
	if !strings.Contains(msg, "tls_min_version") {
		t.Error("should suggest tls_min_version")
	}
	if !strings.Contains(msg, "skip_tls_verify") {
		t.Error("non-STIG should offer skip_tls_verify")
	}
}

func TestBuildTLSDiagnostic_VersionMismatch_STIG(t *testing.T) {
	msg := buildTLSDiagnostic(
		client.TLSError{Kind: client.TLSErrVersionMismatch},
		"https://dns.example.com",
		true,  // stigEnabled
		false, // nss
	)
	if !strings.Contains(msg, "tls_min_version") {
		t.Error("should suggest tls_min_version")
	}
	if strings.Contains(msg, "skip_tls_verify") {
		t.Error("STIG should NOT offer skip_tls_verify")
	}
}

func TestBuildTLSDiagnostic_VersionMismatch_NSS(t *testing.T) {
	msg := buildTLSDiagnostic(
		client.TLSError{Kind: client.TLSErrVersionMismatch},
		"https://dns.example.com",
		true, // stigEnabled
		true, // nss
	)
	if strings.Contains(msg, "tls_min_version") {
		t.Error("NSS should NOT offer tls_min_version fallback")
	}
	if strings.Contains(msg, "skip_tls_verify") {
		t.Error("NSS should NOT offer skip_tls_verify")
	}
	if !strings.Contains(msg, "Upgrade") || !strings.Contains(msg, "TLS 1.3") {
		t.Error("NSS should only suggest upgrading the server")
	}
}

func TestBuildTLSDiagnostic_UnknownAuthority_NoSTIG(t *testing.T) {
	msg := buildTLSDiagnostic(
		client.TLSError{Kind: client.TLSErrUnknownAuthority},
		"https://dns.example.com",
		false, false,
	)
	if !strings.Contains(msg, "ca_cert_file") {
		t.Error("should suggest ca_cert_file")
	}
	if !strings.Contains(msg, "ca_cert_dir") {
		t.Error("should suggest ca_cert_dir")
	}
	if !strings.Contains(msg, "skip_tls_verify") {
		t.Error("non-STIG should offer skip_tls_verify")
	}
}

func TestBuildTLSDiagnostic_UnknownAuthority_NSS(t *testing.T) {
	msg := buildTLSDiagnostic(
		client.TLSError{Kind: client.TLSErrUnknownAuthority},
		"https://dns.example.com",
		true, true,
	)
	if !strings.Contains(msg, "ca_cert_file") {
		t.Error("should suggest ca_cert_file")
	}
	if strings.Contains(msg, "skip_tls_verify") {
		t.Error("NSS should NOT offer skip_tls_verify")
	}
}

func TestBuildTLSDiagnostic_CertificateInvalid_NoSTIG(t *testing.T) {
	msg := buildTLSDiagnostic(
		client.TLSError{Kind: client.TLSErrCertificateInvalid},
		"https://dns.example.com",
		false, false,
	)
	if !strings.Contains(msg, "ca_cert_file") || !strings.Contains(msg, "ca_cert_dir") {
		t.Error("should suggest verifying correct CA chain")
	}
	if !strings.Contains(msg, "skip_tls_verify") {
		t.Error("non-STIG should offer skip_tls_verify")
	}
}

func TestBuildTLSDiagnostic_NotTLS(t *testing.T) {
	msg := buildTLSDiagnostic(
		client.TLSError{Kind: client.TLSErrNotTLS},
		"https://dns.example.com",
		false, false,
	)
	if msg != "" {
		t.Error("non-TLS errors should return empty (pass through original error)")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/provider/... -run "TestBuildTLSDiagnostic" -v`
Expected: FAIL — `buildTLSDiagnostic` undefined

- [ ] **Step 3: Implement buildTLSDiagnostic and Ping probe**

Add to `internal/provider/provider.go`:

```go
// buildTLSDiagnostic creates a context-aware diagnostic message for TLS errors.
// Returns empty string for non-TLS errors (caller should use original error).
func buildTLSDiagnostic(tlsErr client.TLSError, serverURL string, stigEnabled, nss bool) string {
	switch tlsErr.Kind {
	case client.TLSErrVersionMismatch:
		msg := fmt.Sprintf("Connection to %s failed: TLS 1.3 not supported by the server.", serverURL)
		if nss {
			msg += " NSS environments require TLS 1.3 (SC-8). Upgrade the server's TLS configuration to support TLS 1.3."
		} else if stigEnabled {
			msg += " To resolve, either:\n" +
				"  - Upgrade the server's TLS configuration to support TLS 1.3\n" +
				"  - Set tls_min_version = \"1.2\" in the provider configuration (will generate STIG warning)"
		} else {
			msg += " To resolve, either:\n" +
				"  - Upgrade the server's TLS configuration to support TLS 1.3\n" +
				"  - Set tls_min_version = \"1.2\" in the provider configuration\n" +
				"  - Set skip_tls_verify = true to bypass certificate verification entirely"
		}
		return msg

	case client.TLSErrUnknownAuthority:
		msg := fmt.Sprintf("Connection to %s failed: server certificate signed by unknown authority.", serverURL)
		if nss {
			msg += " To resolve:\n" +
				"  - Configure ca_cert_file or ca_cert_dir with the CA certificate that signed the server's certificate"
		} else if stigEnabled {
			msg += " To resolve:\n" +
				"  - Configure ca_cert_file or ca_cert_dir with the CA certificate that signed the server's certificate"
		} else {
			msg += " To resolve, either:\n" +
				"  - Configure ca_cert_file or ca_cert_dir with the CA certificate that signed the server's certificate\n" +
				"  - Set skip_tls_verify = true to bypass certificate verification entirely"
		}
		return msg

	case client.TLSErrCertificateInvalid, client.TLSErrHostnameMismatch:
		msg := fmt.Sprintf("Connection to %s failed: server certificate verification failed.", serverURL)
		if nss || stigEnabled {
			msg += " Verify the correct CA chain is configured in ca_cert_file or ca_cert_dir."
		} else {
			msg += " To resolve, either:\n" +
				"  - Verify the correct CA chain is configured in ca_cert_file or ca_cert_dir\n" +
				"  - Set skip_tls_verify = true to bypass certificate verification entirely"
		}
		return msg

	case client.TLSErrNotTLS:
		return ""
	}
	return ""
}
```

Update the Ping section in `Configure()`:

```go
// Verify connectivity
if err := apiClient.Ping(); err != nil {
	isHTTPS := strings.HasPrefix(serverURL, "https://")
	if isHTTPS {
		tlsErr := client.ClassifyTLSError(err)
		if diagnostic := buildTLSDiagnostic(tlsErr, serverURL, stigEnabled, nssEnabled); diagnostic != "" {
			resp.Diagnostics.AddError("TLS connection failed", diagnostic)
			return
		}
	}
	// Non-TLS error or HTTP URL — pass through original error
	resp.Diagnostics.AddError("Unable to connect to Technitium server",
		fmt.Sprintf("Ping to %s failed: %s", serverURL, err.Error()))
	return
}
```

**IMPORTANT: Configure() reorder required.** The current `Configure()` flow is:
1. Parse server_url, api_token (lines 163-181)
2. Create client + Ping (lines 183-200)
3. Parse STIG config (lines 207-255)
4. SC-8 warning (lines 257-262)

This must be reordered so STIG/NSS booleans are available for tiered diagnostics:
1. Parse server_url, api_token
2. Resolve TLS config (env vars, defaults)
3. Parse STIG config (extract `stigEnabled`, `nssEnabled` booleans)
4. **Run `ValidateProvider()` — STIG validators fire BEFORE Ping** (catches HTTP URL, skip_tls_verify, min version)
5. Create client
6. Ping with tiered TLS error diagnostics (uses `stigEnabled`/`nssEnabled` for context-aware messages)
7. Build provider data

This ordering ensures STIG validators block invalid configs before attempting any network connection, and Ping errors get context-aware diagnostics.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/provider/... -run "TestBuildTLSDiagnostic" -v`
Expected: All PASS

Run: `go test ./internal/client/... ./internal/provider/... -v -count=1`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add internal/provider/provider.go internal/provider/provider_tls_test.go
git commit -m "feat(provider): add tiered TLS diagnostics with Ping-based probe

Context-aware error messages guide users based on STIG/NSS context.
Non-STIG users see skip_tls_verify option. STIG users see CA cert
guidance. NSS users get only server-upgrade guidance. Non-TLS errors
pass through unmodified."
```

---

## Task 7: STIG Engine Extension — TargetProvider, DNS-REQ-028, and ValidateProvider

**Files:**
- Modify: `internal/provider/validators/stig_baselines_gen.go` (add `TargetProvider`, add DNS-REQ-028)
- Modify: `internal/provider/validators/stig_engine.go` (add `ValidateProvider`)
- Create: `internal/provider/validators/stig_engine_provider_test.go`

> **IMPORTANT:** DNS-REQ-001 is for DNSSEC zone signing, NOT TLS transport. Using it for TLS validators would cause cross-suppression issues (suppressing DNS-REQ-001 for TLS would also suppress DNSSEC checks). Create a **new** DNS-REQ-028 requirement specifically for TLS transport encryption.

- [ ] **Step 1: Add DNS-REQ-028 to stig_baselines_gen.go**

Add to the `DNSSecurityRequirements` slice in `internal/provider/validators/stig_baselines_gen.go`:

```go
{
	ID:        "DNS-REQ-028",
	Title:     "Management plane connections must use encrypted transport (TLS)",
	Severity:  "medium",
	Controls:  []string{"SC-8"},
	CCIs:      []string{"CCI-002418", "CCI-002420", "CCI-002421"},
	Provenance: []STIGProvenance{
		{
			RuleID:      "SV-270286r1_rule",
			BenchmarkID: "DNS_Policy",
			Title:       "Management connections to DNS infrastructure must use encrypted transport",
		},
	},
	CheckType: StatelessCheck,
},
```

Add `TargetProvider` to the `TargetResource` constants:

```go
TargetProvider TargetResource = 4
```

Update `validateSuppressIDs` in `provider.go`:
- The validation logic itself derives valid IDs dynamically from `AllRequirementIDs()`, so DNS-REQ-028 will be accepted automatically.
- **Fix the error message** which hardcodes "DNS-REQ-001 through DNS-REQ-027". Change it to derive the range dynamically:
  ```go
  fmt.Sprintf("suppress contains unknown requirement ID: %q. Valid IDs are DNS-REQ-001 through DNS-REQ-%03d.", id, len(validators.DNSSecurityRequirements))
  ```

- [ ] **Step 2: Write failing tests for ValidateProvider**

Create `internal/provider/validators/stig_engine_provider_test.go`:

```go
package validators

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

func TestEngine_ValidateProvider_EmitsFindings(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "strict",
		Categorization: Categorization{
			Confidentiality: "moderate",
			Integrity:       "moderate",
			Availability:    "moderate",
		},
	})

	// Register a provider binding that always fails
	engine.RegisterBindings(TargetProvider, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-028",
			Resource:      TargetProvider,
			Attributes:    []string{"skip_tls_verify"},
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool {
				return false // non-compliant
			},
			Implemented: true,
		},
	})

	var diags diag.Diagnostics
	accessor := NewMockAccessor(map[string]interface{}{
		"skip_tls_verify": true,
	})
	engine.ValidateProvider(context.Background(), accessor, &diags)

	if !diags.HasError() {
		t.Error("strict enforcement should produce error")
	}
}

func TestEngine_ValidateProvider_WarnMode(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:     true,
		Enforcement: "warn",
		Categorization: Categorization{
			Confidentiality: "moderate",
			Integrity:       "moderate",
			Availability:    "moderate",
		},
	})

	engine.RegisterBindings(TargetProvider, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-028",
			Resource:      TargetProvider,
			Attributes:    []string{"skip_tls_verify"},
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool {
				return false
			},
			Implemented: true,
		},
	})

	var diags diag.Diagnostics
	accessor := NewMockAccessor(map[string]interface{}{
		"skip_tls_verify": true,
	})
	engine.ValidateProvider(context.Background(), accessor, &diags)

	if diags.HasError() {
		t.Error("warn mode should not produce errors")
	}
	if len(diags.Warnings()) == 0 {
		t.Error("warn mode should produce warnings")
	}
}

func TestEngine_ValidateProvider_Suppressed(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled:      true,
		Enforcement:  "strict",
		Suppressions: []string{"DNS-REQ-028"},
		Categorization: Categorization{
			Confidentiality: "moderate",
			Integrity:       "moderate",
			Availability:    "moderate",
		},
	})

	engine.RegisterBindings(TargetProvider, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-028",
			Resource:      TargetProvider,
			Attributes:    []string{"skip_tls_verify"},
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool {
				return false
			},
			Implemented: true,
		},
	})

	var diags diag.Diagnostics
	accessor := NewMockAccessor(map[string]interface{}{
		"skip_tls_verify": true,
	})
	engine.ValidateProvider(context.Background(), accessor, &diags)

	if diags.HasError() {
		t.Error("suppressed finding in strict mode should be warning, not error")
	}
}

func TestEngine_ValidateProvider_Disabled(t *testing.T) {
	engine := NewEngine(EngineConfig{
		Enabled: false,
	})

	engine.RegisterBindings(TargetProvider, []ValidatorBinding{
		{
			RequirementID: "DNS-REQ-028",
			Resource:      TargetProvider,
			Attributes:    []string{"skip_tls_verify"},
			StatelessFn: func(ctx context.Context, config ConfigAccessor) bool {
				return false
			},
			Implemented: true,
		},
	})

	var diags diag.Diagnostics
	engine.ValidateProvider(context.Background(), NewMockAccessor(nil), &diags)

	if diags.HasError() || len(diags.Warnings()) > 0 {
		t.Error("disabled engine should produce no diagnostics")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/provider/validators/... -run "TestEngine_ValidateProvider" -v`
Expected: FAIL — `TargetProvider` and `ValidateProvider` undefined

- [ ] **Step 4: Implement ValidateProvider on Engine**

In `internal/provider/validators/stig_engine.go`, add after `ValidatePlan`. This is a thin wrapper that delegates to `ValidateConfig` to avoid code duplication:

```go
// ValidateProvider evaluates provider-level validators during Configure().
// Delegates to ValidateConfig with TargetProvider — same enforcement,
// suppression, and diagnostic logic as resource validators.
func (e *Engine) ValidateProvider(ctx context.Context, config ConfigAccessor, diags *diag.Diagnostics) {
	e.ValidateConfig(ctx, TargetProvider, config, diags)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/provider/validators/... -run "TestEngine_ValidateProvider" -v`
Expected: All 4 tests PASS

- [ ] **Step 6: Commit**

```bash
git add internal/provider/validators/stig_baselines_gen.go internal/provider/validators/stig_engine.go internal/provider/validators/stig_engine_provider_test.go
git commit -m "feat(stig): add TargetProvider, DNS-REQ-028, and ValidateProvider

New DNS-REQ-028 requirement for TLS transport encryption (SC-8), separate
from DNS-REQ-001 (DNSSEC). ValidateProvider delegates to ValidateConfig
with TargetProvider to avoid code duplication."
```

---

## Task 8: TLS STIG Validators

**Files:**
- Modify: `internal/provider/validators/stig.go`
- Modify: `internal/provider/validators/stig_test.go`

- [ ] **Step 1: Write failing tests for TLS validators**

Add to `internal/provider/validators/stig_test.go` (or create a new `stig_tls_validators_test.go`):

```go
package validators

import (
	"context"
	"testing"
)

func TestValidateTLSEnabled_HTTP_Fails(t *testing.T) {
	accessor := NewMockAccessor(map[string]interface{}{
		"server_url": "http://dns.example.com",
	})
	if validateTLSEnabled(context.Background(), accessor) {
		t.Error("HTTP URL should fail TLS enabled check")
	}
}

func TestValidateTLSEnabled_HTTPS_Passes(t *testing.T) {
	accessor := NewMockAccessor(map[string]interface{}{
		"server_url": "https://dns.example.com",
	})
	if !validateTLSEnabled(context.Background(), accessor) {
		t.Error("HTTPS URL should pass TLS enabled check")
	}
}

func TestValidateTLSEnabled_NullURL_Passes(t *testing.T) {
	accessor := NewMockAccessor(nil)
	if !validateTLSEnabled(context.Background(), accessor) {
		t.Error("null URL should pass (cannot validate)")
	}
}

func TestValidateTLSMinVersion_12_Fails(t *testing.T) {
	accessor := NewMockAccessor(map[string]interface{}{
		"tls_min_version": "1.2",
	})
	if validateTLSMinVersion(context.Background(), accessor) {
		t.Error("TLS 1.2 should fail min version check")
	}
}

func TestValidateTLSMinVersion_13_Passes(t *testing.T) {
	accessor := NewMockAccessor(map[string]interface{}{
		"tls_min_version": "1.3",
	})
	if !validateTLSMinVersion(context.Background(), accessor) {
		t.Error("TLS 1.3 should pass min version check")
	}
}

func TestValidateTLSMinVersion_Null_Passes(t *testing.T) {
	// Null means default (1.3) — compliant
	accessor := NewMockAccessor(nil)
	if !validateTLSMinVersion(context.Background(), accessor) {
		t.Error("null (default 1.3) should pass")
	}
}

func TestValidateTLSVerification_SkipTrue_Fails(t *testing.T) {
	accessor := NewMockAccessor(map[string]interface{}{
		"skip_tls_verify": true, // bool, not string — MockAccessor uses type assertion
	})
	if validateTLSVerification(context.Background(), accessor) {
		t.Error("skip_tls_verify=true should fail verification check")
	}
}

func TestValidateTLSVerification_SkipFalse_Passes(t *testing.T) {
	accessor := NewMockAccessor(map[string]interface{}{
		"skip_tls_verify": false,
	})
	if !validateTLSVerification(context.Background(), accessor) {
		t.Error("skip_tls_verify=false should pass")
	}
}

func TestValidateTLSVerification_Null_Passes(t *testing.T) {
	accessor := NewMockAccessor(nil)
	if !validateTLSVerification(context.Background(), accessor) {
		t.Error("null (default false) should pass")
	}
}
```

> **Note:** Uses the existing `NewMockAccessor(map[string]interface{}{...})` constructor from `accessors.go`. Boolean values must be actual `bool` type (not string `"true"`) because `GetBool` uses `v.(bool)` type assertion.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/provider/validators/... -run "TestValidateTLS" -v`
Expected: FAIL — validator functions undefined

- [ ] **Step 3: Implement TLS validators and ProviderBindings**

Add to `internal/provider/validators/stig.go`:

```go
// ProviderBindings defines STIG validators for provider-level TLS configuration.
// Uses DNS-REQ-028 (TLS transport encryption), NOT DNS-REQ-001 (DNSSEC zone signing).
// This separation ensures suppressing TLS checks doesn't suppress DNSSEC checks.
var ProviderBindings = []ValidatorBinding{
	{
		RequirementID: "DNS-REQ-028", // SC-8: Management plane encrypted transport
		Resource:      TargetProvider,
		Attributes:    []string{"server_url"},
		StatelessFn:   validateTLSEnabled,
		Implemented:   true,
	},
	{
		RequirementID: "DNS-REQ-028",
		Resource:      TargetProvider,
		Attributes:    []string{"tls_min_version"},
		StatelessFn:   validateTLSMinVersion,
		Implemented:   true,
	},
	{
		RequirementID: "DNS-REQ-028",
		Resource:      TargetProvider,
		Attributes:    []string{"skip_tls_verify"},
		StatelessFn:   validateTLSVerification,
		Implemented:   true,
	},
}

// validateTLSEnabled checks that server_url uses HTTPS (SC-8).
func validateTLSEnabled(ctx context.Context, config ConfigAccessor) bool {
	url, ok := config.GetString("server_url")
	if !ok {
		return true // null — cannot validate
	}
	return strings.HasPrefix(url, "https://")
}

// validateTLSMinVersion checks that tls_min_version is "1.3" (SC-8).
func validateTLSMinVersion(ctx context.Context, config ConfigAccessor) bool {
	version, ok := config.GetString("tls_min_version")
	if !ok {
		return true // null — default is 1.3, compliant
	}
	return version == "1.3"
}

// validateTLSVerification checks that skip_tls_verify is false (SC-8).
func validateTLSVerification(ctx context.Context, config ConfigAccessor) bool {
	skip, ok := config.GetBool("skip_tls_verify")
	if !ok {
		return true // null — default is false, compliant
	}
	return !skip
}
```

- [ ] **Step 4: Update AllBindings() and structural tests**

In `internal/provider/validators/stig.go`, update the `AllBindings()` function to include `ProviderBindings`:

```go
func AllBindings() []ValidatorBinding {
	var all []ValidatorBinding
	all = append(all, ZoneBindings...)
	all = append(all, ServerSettingsBindings...)
	all = append(all, RecordBindings...)
	all = append(all, TSIGKeyBindings...)
	all = append(all, ProviderBindings...)
	return all
}
```

The structural tests (`TestBindings_AllRequirementsBound`, etc.) use `AllBindings()`, so they will automatically pick up `ProviderBindings` once the function is updated.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/provider/validators/... -v -count=1`
Expected: All tests PASS (new + existing structural tests)

- [ ] **Step 6: Commit**

```bash
git add internal/provider/validators/stig.go internal/provider/validators/stig_test.go
git commit -m "feat(stig): add TLS provider-level validators for DNS-REQ-028 (SC-8)

Three validators: validateTLSEnabled (HTTP vs HTTPS), validateTLSMinVersion
(1.3 required), validateTLSVerification (skip_tls_verify must be false).
Registered as ProviderBindings under TargetProvider with DNS-REQ-028."
```

---

## Task 9: Wire Up Engine in Configure() and Remove Hardcoded SC-8 Warning

**Files:**
- Modify: `internal/provider/provider.go`

- [ ] **Step 1: Register ProviderBindings in Configure()**

In the engine construction section of `Configure()` (around line 265-282), add `ProviderBindings` registration:

```go
stigEngine.RegisterBindings(validators.TargetProvider, validators.ProviderBindings)
```

Add this alongside the existing `RegisterBindings` calls for Zone, ServerSettings, Record, TSIGKey.

- [ ] **Step 2: Call ValidateProvider after engine construction**

After the engine is constructed and all bindings registered, add a `ProviderConfigAccessor` and call `ValidateProvider`:

```go
// Build provider config accessor for provider-level STIG validators
providerAccessor := &providerConfigAccessor{
	serverURL:     serverURL,
	skipTLSVerify: skipTLSVerify,
	tlsMinVersion: tlsMinVersion,
}
stigEngine.ValidateProvider(ctx, providerAccessor, &resp.Diagnostics)
if resp.Diagnostics.HasError() {
	return
}
```

Implement the accessor:

```go
// providerConfigAccessor adapts provider configuration for STIG validator access.
type providerConfigAccessor struct {
	serverURL     string
	skipTLSVerify bool
	tlsMinVersion string
}

func (a *providerConfigAccessor) GetString(path string) (string, bool) {
	switch path {
	case "server_url":
		return a.serverURL, true
	case "tls_min_version":
		if a.tlsMinVersion == "" {
			return "", false
		}
		return a.tlsMinVersion, true
	default:
		return "", false
	}
}

func (a *providerConfigAccessor) GetBool(path string) (bool, bool) {
	switch path {
	case "skip_tls_verify":
		// Always returns ok=true because the resolved value always exists
		// after resolveTLSBool (explicit default). This means the validator
		// always evaluates — which is correct since the default (false) is compliant.
		return a.skipTLSVerify, true
	default:
		return false, false
	}
}

func (a *providerConfigAccessor) GetStringList(path string) ([]string, bool) {
	return nil, false
}
```

- [ ] **Step 3: Remove the hardcoded SC-8 warning**

Delete the existing hardcoded warning block (around lines 257-262):

```go
// REMOVE THIS BLOCK:
// STIG warning for skip_tls_verify
if providerData.STIGEnabled && skipTLSVerify {
	resp.Diagnostics.AddWarning("STIG SC-8: TLS verification disabled",
		"skip_tls_verify = true disables TLS certificate verification. "+
			"This violates STIG requirement SC-8 (Transmission Confidentiality and Integrity).")
}
```

This is now handled by `validateTLSVerification` through the engine.

- [ ] **Step 4: Run all tests**

Run: `go test ./internal/client/... ./internal/provider/... -v -count=1`
Expected: All PASS. Verify no regression in STIG acceptance tests.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/provider.go
git commit -m "feat(provider): wire STIG engine for provider-level TLS validation

Registers ProviderBindings, calls ValidateProvider during Configure().
Removes hardcoded SC-8 warning — now handled by unified engine with
enforcement mode, suppression, and RMF traceability."
```

---

## Task 10: Acceptance Tests

**Files:**
- Modify: `internal/provider/stig_acceptance_test.go`

- [ ] **Step 1: Add STIG TLS acceptance tests**

Add to `internal/provider/stig_acceptance_test.go`:

```go
func TestAccSTIG_Strict_HTTP_PlanFails(t *testing.T) {
	// STIG strict + HTTP URL should produce SC-8 error
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfigHTTP("strict", nil, "moderate") + `
data "technitium_zones" "test" {}
`,
				ExpectError: regexp.MustCompile(`DNS-REQ-028.*SC-8`),
			},
		},
	})
}

func TestAccSTIG_Warn_HTTP_PlanSucceeds(t *testing.T) {
	// STIG warn + HTTP URL should warn but not error
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfigHTTP("warn", nil, "moderate") + `
data "technitium_zones" "test" {}
`,
				// No ExpectError — should succeed with warning
			},
		},
	})
}

func TestAccSTIG_Strict_SkipTLSVerify_PlanFails(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfigSkipTLS("strict", nil, "moderate") + `
data "technitium_zones" "test" {}
`,
				ExpectError: regexp.MustCompile(`DNS-REQ-028.*SC-8`),
			},
		},
	})
}

func TestAccSTIG_Suppress_TLSReq_SkipVerify_Succeeds(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSTIGProviderConfigSkipTLS("strict", []string{"DNS-REQ-028"}, "moderate") + `
data "technitium_zones" "test" {}
`,
				// Suppressed — should succeed (warning only)
			},
		},
	})
}
```

Add helper functions:

```go
func testAccSTIGProviderConfigHTTP(enforcement string, suppress []string, baseline string) string {
	// Uses http:// URL to trigger validateTLSEnabled
	// ValidateProvider fires BEFORE Ping, so STIG errors are caught before connectivity check
	suppressStr := "[]"
	if len(suppress) > 0 {
		items := make([]string, len(suppress))
		for i, s := range suppress {
			items[i] = fmt.Sprintf("%q", s)
		}
		suppressStr = fmt.Sprintf("[%s]", strings.Join(items, ", "))
	}
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://localhost:5380"
  api_token  = %q

  stig_compliance {
    enabled     = true
    enforcement = %q
    suppress    = %s

    categorization {
      baseline = %q
    }
  }
}
`, testAccAPIToken(), enforcement, suppressStr, baseline)
}

func testAccSTIGProviderConfigSkipTLS(enforcement string, suppress []string, baseline string) string {
	// ValidateProvider fires BEFORE Ping, so STIG errors are caught before connectivity check
	suppressStr := "[]"
	if len(suppress) > 0 {
		items := make([]string, len(suppress))
		for i, s := range suppress {
			items[i] = fmt.Sprintf("%q", s)
		}
		suppressStr = fmt.Sprintf("[%s]", strings.Join(items, ", "))
	}
	return fmt.Sprintf(`
provider "technitium" {
  server_url      = "https://localhost:5380"
  api_token       = %q
  skip_tls_verify = true

  stig_compliance {
    enabled     = true
    enforcement = %q
    suppress    = %s

    categorization {
      baseline = %q
    }
  }
}
`, testAccAPIToken(), enforcement, suppressStr, baseline)
}
```

- [ ] **Step 2: Run acceptance tests**

Run: `TF_ACC=1 go test ./internal/provider/... -run "TestAccSTIG_.*TLS\|TestAccSTIG_.*HTTP" -v -timeout 120s`
Expected: All PASS

- [ ] **Step 3: Run full test suite**

Run: `go test ./... -v -count=1`
Expected: All tests PASS — no regressions.

- [ ] **Step 4: Verify FIPS build**

Run: `GOEXPERIMENT=boringcrypto go build ./...`
Expected: Clean build, no errors.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/stig_acceptance_test.go
git commit -m "test(stig): add acceptance tests for TLS provider-level validators

Tests SC-8 enforcement for HTTP URLs and skip_tls_verify under strict,
warn, and suppression modes. Validates engine integration in Configure()."
```

---

## Task 11: Final Cleanup and Verification

- [ ] **Step 1: Run full test suite one more time**

Run: `go test ./... -v -count=1 -timeout 300s`
Expected: All PASS

- [ ] **Step 2: Run go vet and staticcheck**

Run: `go vet ./...`
Run: `staticcheck ./...` (if available)
Expected: No issues

- [ ] **Step 3: Verify FIPS build**

Run: `GOEXPERIMENT=boringcrypto go build ./...`
Expected: Clean

- [ ] **Step 4: Final commit if any cleanup needed**

If any minor cleanup was needed, commit with:
```bash
git commit -m "chore: final cleanup for Vault-style TLS configuration"
```
