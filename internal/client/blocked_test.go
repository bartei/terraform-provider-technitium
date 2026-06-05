// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestExportFilteredZones_TokenInBodyNotURL(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if strings.Contains(r.URL.RawQuery, "test-token") {
			t.Error("token value leaked into the request URL")
		}
		if r.FormValue("token") != "test-token" {
			t.Error("token not passed in form body")
		}
		_, _ = w.Write([]byte("example.com\nads.example.net\n"))
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	domains, err := c.BlockedZoneList(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 2 || domains[0] != "example.com" || domains[1] != "ads.example.net" {
		t.Errorf("unexpected domains: %v", domains)
	}
}

func TestExportFilteredZones_EmptyList(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(""))
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	domains, err := c.BlockedZoneList(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 0 {
		t.Errorf("expected empty list, got %v", domains)
	}
}

func TestExportFilteredZones_HTTPErrorNotParsedAsDomains(t *testing.T) {
	// An error page body must surface as an error, not be parsed
	// line-by-line into a bogus domain list.
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error\nstack trace line"))
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	_, err := c.BlockedZoneList(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected status code in error, got: %v", err)
	}
}

func TestExportFilteredZones_InvalidTokenEnvelope(t *testing.T) {
	// Technitium returns HTTP 200 with a JSON error envelope for an
	// invalid token even on plain-text endpoints; it must be detected.
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"invalid-token","errorMessage":"The session has expired."}`))
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "expired"})
	_, err := c.BlockedZoneList(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid-token envelope")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError in chain (got %T: %v)", err, err)
	}
	if !apiErr.IsInvalidToken() {
		t.Error("expected IsInvalidToken() to be true")
	}
}

func TestAllowedZoneList_UsesExportTransport(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/allowed/export" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.FormValue("token") != "test-token" {
			t.Error("token not passed in form body")
		}
		_, _ = w.Write([]byte("good.example.org\n"))
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	domains, err := c.AllowedZoneList(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 1 || domains[0] != "good.example.org" {
		t.Errorf("unexpected domains: %v", domains)
	}
}
