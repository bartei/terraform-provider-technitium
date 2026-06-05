// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestRecordAdd(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/records/add" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		checks := map[string]string{
			"domain":    "www.example.com",
			"zone":      "example.com",
			"type":      "A",
			"ttl":       "3600",
			"overwrite": "true",
			"ipAddress": "10.0.0.1",
		}
		for k, want := range checks {
			if got := r.FormValue(k); got != want {
				t.Errorf("param %s: got %q, want %q", k, got, want)
			}
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:   "ok",
			Response: json.RawMessage(`{"zone":{"name":"example.com"},"addedRecord":{"name":"www.example.com","type":"A","ttl":3600,"disabled":false,"rData":{"ipAddress":"10.0.0.1"}}}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	rec, err := c.RecordAdd(context.Background(), "www.example.com", "example.com", "A", 3600, true, map[string]string{"ipAddress": "10.0.0.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Name != "www.example.com" || rec.Type != "A" || rec.TTL != 3600 {
		t.Errorf("unexpected record: %+v", rec)
	}
	if rec.RData["ipAddress"] != "10.0.0.1" {
		t.Errorf("unexpected rData: %+v", rec.RData)
	}
}

func TestRecordAdd_OmitsTTLandOverwriteWhenDefault(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.PostForm == nil {
			_ = r.ParseForm()
		}
		if r.PostForm.Has("ttl") {
			t.Error("ttl must be omitted when not positive")
		}
		if r.PostForm.Has("overwrite") {
			t.Error("overwrite must be omitted when false")
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:   "ok",
			Response: json.RawMessage(`{"addedRecord":{"name":"x","type":"CNAME","rData":{"cname":"y"}}}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if _, err := c.RecordAdd(context.Background(), "x", "z", "CNAME", 0, false, map[string]string{"cname": "y"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRecordGet(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/records/get" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.FormValue("domain") != "example.com" || r.FormValue("zone") != "example.com" {
			t.Errorf("unexpected params: %v", r.PostForm)
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status: "ok",
			Response: json.RawMessage(`{"zone":{"name":"example.com"},"records":[
				{"name":"example.com","type":"MX","ttl":3600,"rData":{"preference":10,"exchange":"mail.example.com"}},
				{"name":"example.com","type":"TXT","ttl":300,"rData":{"text":"hello"}}
			]}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	recs, err := c.RecordGet(context.Background(), "example.com", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 2 || recs[0].Type != "MX" || recs[1].Type != "TXT" {
		t.Fatalf("unexpected records: %+v", recs)
	}
}

func TestRecordUpdate(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/records/update" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		checks := map[string]string{
			"domain":       "www.example.com",
			"zone":         "example.com",
			"type":         "A",
			"ttl":          "7200",
			"ipAddress":    "10.0.0.1",
			"newIpAddress": "10.0.0.2",
		}
		for k, want := range checks {
			if got := r.FormValue(k); got != want {
				t.Errorf("param %s: got %q, want %q", k, got, want)
			}
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	err := c.RecordUpdate(context.Background(), "www.example.com", "example.com", "A", 7200, map[string]string{
		"ipAddress":    "10.0.0.1",
		"newIpAddress": "10.0.0.2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRecordUpdate_OmitsTTLWhenZero(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.PostForm == nil {
			_ = r.ParseForm()
		}
		if r.PostForm.Has("ttl") {
			t.Error("ttl must be omitted when not positive")
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.RecordUpdate(context.Background(), "d", "z", "CNAME", 0, map[string]string{"cname": "y"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRecordDelete(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/records/delete" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		checks := map[string]string{
			"domain":     "example.com",
			"zone":       "example.com",
			"type":       "MX",
			"exchange":   "mail.example.com",
			"preference": "10",
		}
		for k, want := range checks {
			if got := r.FormValue(k); got != want {
				t.Errorf("param %s: got %q, want %q", k, got, want)
			}
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	err := c.RecordDelete(context.Background(), "example.com", "example.com", "MX", map[string]string{
		"exchange":   "mail.example.com",
		"preference": "10",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRecordDelete_APIErrorPropagates(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "error", ErrorMessage: "record does not exist"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.RecordDelete(context.Background(), "d", "z", "A", map[string]string{"ipAddress": "1.1.1.1"}); err == nil {
		t.Fatal("expected error to propagate")
	}
}

func TestRecordValueParam(t *testing.T) {
	cases := map[string]string{
		"A":       "ipAddress",
		"AAAA":    "ipAddress",
		"CNAME":   "cname",
		"MX":      "exchange",
		"TXT":     "text",
		"SRV":     "target",
		"PTR":     "ptrName",
		"NS":      "nameServer",
		"CAA":     "value",
		"UNKNOWN": "value",
	}
	for recordType, want := range cases {
		if got := RecordValueParam(recordType); got != want {
			t.Errorf("RecordValueParam(%q) = %q, want %q", recordType, got, want)
		}
	}
}

func TestRecordValueFromRData(t *testing.T) {
	cases := []struct {
		name       string
		recordType string
		rData      map[string]interface{}
		want       string
	}{
		{"A string", "A", map[string]interface{}{"ipAddress": "10.0.0.1"}, "10.0.0.1"},
		{"CNAME", "CNAME", map[string]interface{}{"cname": "alias.example.com"}, "alias.example.com"},
		{"MX exchange", "MX", map[string]interface{}{"exchange": "mail.example.com", "preference": float64(10)}, "mail.example.com"},
		{"SRV target", "SRV", map[string]interface{}{"target": "svc.example.com"}, "svc.example.com"},
		{"NS", "NS", map[string]interface{}{"nameServer": "ns1.example.com"}, "ns1.example.com"},
		{"numeric coerced to string", "CAA", map[string]interface{}{"value": float64(42)}, "42"},
		{"missing key", "A", map[string]interface{}{"other": "x"}, ""},
		{"nil map", "A", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RecordValueFromRData(tc.recordType, tc.rData); got != tc.want {
				t.Errorf("RecordValueFromRData(%q, %+v) = %q, want %q", tc.recordType, tc.rData, got, tc.want)
			}
		})
	}
}
