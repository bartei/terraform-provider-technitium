// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// tsigSettingsServer returns a server that answers /api/settings/get with the
// given keys and records any tsigKeys value sent to /api/settings/set.
func tsigSettingsServer(t *testing.T, keys []TSIGKey, gotSet *string) *http.HandlerFunc {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/settings/get":
			payload, err := json.Marshal(struct {
				TsigKeys []TSIGKey `json:"tsigKeys"`
			}{TsigKeys: keys})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok", Response: payload}); err != nil {
				t.Fatalf("encode: %v", err)
			}
		case "/api/settings/set":
			if gotSet != nil {
				*gotSet = r.FormValue("tsigKeys")
			}
			if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
				t.Fatalf("encode: %v", err)
			}
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	return &h
}

func TestTSIGKeyList_Empty(t *testing.T) {
	// settings/get with null tsigKeys must yield a non-nil empty slice.
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok", Response: json.RawMessage(`{"tsigKeys":null}`)}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	keys, err := c.TSIGKeyList(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keys == nil {
		t.Fatal("expected non-nil slice")
	}
	if len(keys) != 0 {
		t.Errorf("expected empty, got %+v", keys)
	}
}

func TestTSIGKeyList_Multiple(t *testing.T) {
	keys := []TSIGKey{
		{KeyName: "k1", SharedSecret: "s1", AlgorithmName: "hmac-sha256"},
		{KeyName: "k2", SharedSecret: "s2", AlgorithmName: "hmac-sha512"},
	}
	h := tsigSettingsServer(t, keys, nil)
	ts := newTestServer(t, *h)
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	got, err := c.TSIGKeyList(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[1].AlgorithmName != "hmac-sha512" {
		t.Errorf("unexpected keys: %+v", got)
	}
}

func TestTSIGKeyGet_FoundCaseInsensitive(t *testing.T) {
	keys := []TSIGKey{{KeyName: "MyKey", SharedSecret: "secret", AlgorithmName: "hmac-sha256"}}
	h := tsigSettingsServer(t, keys, nil)
	ts := newTestServer(t, *h)
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	key, err := c.TSIGKeyGet(context.Background(), "mykey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.KeyName != "MyKey" || key.SharedSecret != "secret" {
		t.Errorf("unexpected key: %+v", key)
	}
}

func TestTSIGKeyGet_NotFound(t *testing.T) {
	h := tsigSettingsServer(t, []TSIGKey{{KeyName: "other"}}, nil)
	ts := newTestServer(t, *h)
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	_, err := c.TSIGKeyGet(context.Background(), "missing")
	if !errors.Is(err, ErrTSIGKeyNotFound) {
		t.Fatalf("expected ErrTSIGKeyNotFound, got %v", err)
	}
}

func TestTSIGKeyCreate_PipeWireFormat(t *testing.T) {
	// Two existing keys; create appends a third. Wire format is name|secret|algo
	// joined across all keys with no trailing/leading delimiter.
	existing := []TSIGKey{
		{KeyName: "k1", SharedSecret: "s1", AlgorithmName: "hmac-sha256"},
		{KeyName: "k2", SharedSecret: "s2", AlgorithmName: "hmac-sha512"},
	}
	var got string
	h := tsigSettingsServer(t, existing, &got)
	ts := newTestServer(t, *h)
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	err := c.TSIGKeyCreate(context.Background(), TSIGKey{KeyName: "k3", SharedSecret: "s3", AlgorithmName: "hmac-md5"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "k1|s1|hmac-sha256|k2|s2|hmac-sha512|k3|s3|hmac-md5"
	if got != want {
		t.Errorf("wire format mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestTSIGKeyCreate_RejectsPipeInFields(t *testing.T) {
	// A pipe in any field would corrupt the wire format and must be rejected
	// before any settings/set call is made.
	called := false
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/settings/set" {
			called = true
		}
		// Still answer settings/get in case list runs first.
		_ = json.NewEncoder(w).Encode(APIResponse{Status: "ok", Response: json.RawMessage(`{"tsigKeys":[]}`)})
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	err := c.TSIGKeyCreate(context.Background(), TSIGKey{KeyName: "bad|name", SharedSecret: "s", AlgorithmName: "hmac-sha256"})
	if err == nil {
		t.Fatal("expected validation error for pipe in field")
	}
	if !strings.Contains(err.Error(), "must not contain '|'") {
		t.Errorf("unexpected error: %v", err)
	}
	if called {
		t.Error("settings/set must not be called when validation fails")
	}
}

func TestTSIGKeyCreate_DuplicateRejected(t *testing.T) {
	existing := []TSIGKey{{KeyName: "dupe", SharedSecret: "s", AlgorithmName: "hmac-sha256"}}
	var got string
	h := tsigSettingsServer(t, existing, &got)
	ts := newTestServer(t, *h)
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	err := c.TSIGKeyCreate(context.Background(), TSIGKey{KeyName: "DUPE", SharedSecret: "x", AlgorithmName: "hmac-sha256"})
	if err == nil {
		t.Fatal("expected duplicate error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}
	if got != "" {
		t.Error("settings/set must not be called for a duplicate create")
	}
}

func TestTSIGKeyCreate_FromEmptyList(t *testing.T) {
	var got string
	h := tsigSettingsServer(t, nil, &got)
	ts := newTestServer(t, *h)
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.TSIGKeyCreate(context.Background(), TSIGKey{KeyName: "only", SharedSecret: "s", AlgorithmName: "hmac-sha256"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "only|s|hmac-sha256" {
		t.Errorf("unexpected wire value %q", got)
	}
}

func TestTSIGKeyUpdate_ReplacesExisting(t *testing.T) {
	existing := []TSIGKey{
		{KeyName: "k1", SharedSecret: "old", AlgorithmName: "hmac-sha256"},
		{KeyName: "k2", SharedSecret: "s2", AlgorithmName: "hmac-sha512"},
	}
	var got string
	h := tsigSettingsServer(t, existing, &got)
	ts := newTestServer(t, *h)
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	err := c.TSIGKeyUpdate(context.Background(), TSIGKey{KeyName: "k1", SharedSecret: "new", AlgorithmName: "hmac-sha384"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "k1|new|hmac-sha384|k2|s2|hmac-sha512"
	if got != want {
		t.Errorf("wire mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestTSIGKeyUpdate_NotFound(t *testing.T) {
	var got string
	h := tsigSettingsServer(t, []TSIGKey{{KeyName: "k1"}}, &got)
	ts := newTestServer(t, *h)
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	err := c.TSIGKeyUpdate(context.Background(), TSIGKey{KeyName: "ghost", SharedSecret: "s", AlgorithmName: "hmac-sha256"})
	if !errors.Is(err, ErrTSIGKeyNotFound) {
		t.Fatalf("expected ErrTSIGKeyNotFound, got %v", err)
	}
	if got != "" {
		t.Error("settings/set must not be called when key to update is missing")
	}
}

func TestTSIGKeyUpdate_RejectsPipe(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(APIResponse{Status: "ok", Response: json.RawMessage(`{"tsigKeys":[]}`)})
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	err := c.TSIGKeyUpdate(context.Background(), TSIGKey{KeyName: "k", SharedSecret: "se|cret", AlgorithmName: "hmac-sha256"})
	if err == nil || !strings.Contains(err.Error(), "must not contain '|'") {
		t.Fatalf("expected pipe validation error, got %v", err)
	}
}

func TestTSIGKeyDelete_RemovesAndRewrites(t *testing.T) {
	existing := []TSIGKey{
		{KeyName: "k1", SharedSecret: "s1", AlgorithmName: "hmac-sha256"},
		{KeyName: "k2", SharedSecret: "s2", AlgorithmName: "hmac-sha512"},
	}
	var got string
	h := tsigSettingsServer(t, existing, &got)
	ts := newTestServer(t, *h)
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.TSIGKeyDelete(context.Background(), "K1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "k2|s2|hmac-sha512" {
		t.Errorf("unexpected wire value %q", got)
	}
}

func TestTSIGKeyDelete_LastKeyClearsAll(t *testing.T) {
	// Deleting the only key results in an empty list, which writes tsigKeys=false.
	existing := []TSIGKey{{KeyName: "only", SharedSecret: "s", AlgorithmName: "hmac-sha256"}}
	var got string
	h := tsigSettingsServer(t, existing, &got)
	ts := newTestServer(t, *h)
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.TSIGKeyDelete(context.Background(), "only"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "false" {
		t.Errorf("expected tsigKeys=false when clearing all keys, got %q", got)
	}
}

func TestTSIGKeyDelete_MissingIsIdempotent(t *testing.T) {
	// Deleting a key that is not present must succeed and must NOT issue a
	// settings/set write (nothing changed).
	existing := []TSIGKey{{KeyName: "k1", SharedSecret: "s1", AlgorithmName: "hmac-sha256"}}
	var got string
	setWasCalled := false
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/settings/get":
			payload, _ := json.Marshal(struct {
				TsigKeys []TSIGKey `json:"tsigKeys"`
			}{TsigKeys: existing})
			_ = json.NewEncoder(w).Encode(APIResponse{Status: "ok", Response: payload})
		case "/api/settings/set":
			setWasCalled = true
			got = r.FormValue("tsigKeys")
			_ = json.NewEncoder(w).Encode(APIResponse{Status: "ok"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.TSIGKeyDelete(context.Background(), "ghost"); err != nil {
		t.Fatalf("expected idempotent delete, got %v", err)
	}
	if setWasCalled {
		t.Errorf("settings/set must not be called for a no-op delete (got %q)", got)
	}
}

func TestTSIGKeyDelete_ListErrorPropagates(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(APIResponse{Status: "error", ErrorMessage: "boom"})
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.TSIGKeyDelete(context.Background(), "k1"); err == nil {
		t.Fatal("expected error to propagate from settings/get")
	}
}
