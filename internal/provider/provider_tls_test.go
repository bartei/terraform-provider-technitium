// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/bartei/terraform-provider-technitium/internal/client"
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
	// Explicitly clear so the test is robust against TECHNITIUM_CACERT being
	// set in the parent process environment (which happens under
	// `make testacc-up-tls`).
	t.Setenv("TECHNITIUM_CACERT", "")
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

func ptrBool(b bool) *bool { return &b }

func TestBuildTLSDiagnostic_VersionMismatch(t *testing.T) {
	msg := buildTLSDiagnostic(client.TLSError{Kind: client.TLSErrVersionMismatch}, "https://dns.example.com")
	if !strings.Contains(msg, "TLS 1.3 not supported") {
		t.Errorf("expected version mismatch message, got: %s", msg)
	}
	if !strings.Contains(msg, "tls_min_version") {
		t.Error("should offer tls_min_version fallback")
	}
	if !strings.Contains(msg, "skip_tls_verify") {
		t.Error("should offer skip_tls_verify")
	}
}

func TestBuildTLSDiagnostic_UnknownAuthority(t *testing.T) {
	msg := buildTLSDiagnostic(client.TLSError{Kind: client.TLSErrUnknownAuthority}, "https://dns.example.com")
	if !strings.Contains(msg, "unknown authority") {
		t.Errorf("expected unknown authority message, got: %s", msg)
	}
	if !strings.Contains(msg, "ca_cert_file") {
		t.Error("should suggest ca_cert_file")
	}
	if !strings.Contains(msg, "skip_tls_verify") {
		t.Error("should offer skip_tls_verify")
	}
}

func TestBuildTLSDiagnostic_CertificateInvalid(t *testing.T) {
	msg := buildTLSDiagnostic(client.TLSError{Kind: client.TLSErrCertificateInvalid}, "https://dns.example.com")
	if !strings.Contains(msg, "certificate verification failed") {
		t.Errorf("expected certificate invalid message, got: %s", msg)
	}
	if !strings.Contains(msg, "skip_tls_verify") {
		t.Error("should offer skip_tls_verify")
	}
}

func TestBuildTLSDiagnostic_NotTLS_ReturnsEmpty(t *testing.T) {
	msg := buildTLSDiagnostic(client.TLSError{Kind: client.TLSErrNotTLS}, "https://dns.example.com")
	if msg != "" {
		t.Errorf("expected empty string for non-TLS error, got: %s", msg)
	}
}
