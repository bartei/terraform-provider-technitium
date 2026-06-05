// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestSettingsGet_FieldMapping(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/settings/get" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status: "ok",
			Response: json.RawMessage(`{
				"version":"13.0","dnsServerDomain":"dns.local","dnssecValidation":true,
				"recursion":"AllowOnlyForPrivateNetworks","recursionNetworkACL":["192.168.0.0/16"],
				"qnameMinimization":true,"logQueries":false,"maxLogFileDays":30,
				"enableBlocking":true,"blockingType":"NxDomain","blockingAnswerTtl":60,
				"customBlockingAddresses":["0.0.0.0"],"blockListUrls":["https://example.com/list.txt"],
				"blockListUpdateIntervalHours":24,
				"forwarders":["1.1.1.1","8.8.8.8"],"forwarderProtocol":"Tcp",
				"enableDnsOverTls":true,"enableDnsOverHttps":false,
				"udpPayloadSize":1232,"cacheMinimumRecordTtl":10,"cacheMaximumRecordTtl":86400,
				"tsigKeys":[{"keyName":"k1","sharedSecret":"s1","algorithmName":"hmac-sha256"}]
			}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	s, err := c.SettingsGet(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Version != "13.0" || s.DnsServerDomain != "dns.local" || !s.DnssecValidation {
		t.Errorf("unexpected top-level fields: %+v", s)
	}
	if s.Recursion != "AllowOnlyForPrivateNetworks" || len(s.RecursionNetworkACL) != 1 {
		t.Errorf("unexpected recursion fields: %+v", s)
	}
	if !s.EnableBlocking || s.BlockingType != BlockingTypeNxDomain || s.BlockingAnswerTTL != 60 {
		t.Errorf("unexpected blocking fields: %+v", s)
	}
	if s.BlockListUpdateIntervalHours != 24 || len(s.BlockListUrls) != 1 {
		t.Errorf("unexpected blocklist fields: %+v", s)
	}
	if len(s.Forwarders) != 2 || s.ForwarderProtocol != "Tcp" || !s.EnableDnsOverTls {
		t.Errorf("unexpected forwarder fields: %+v", s)
	}
	if s.UdpPayloadSize != 1232 || s.CacheMinimumRecordTtl != 10 || s.CacheMaximumRecordTtl != 86400 {
		t.Errorf("unexpected cache fields: %+v", s)
	}
	if len(s.TsigKeys) != 1 || s.TsigKeys[0].KeyName != "k1" || s.TsigKeys[0].AlgorithmName != "hmac-sha256" {
		t.Errorf("unexpected tsig keys: %+v", s.TsigKeys)
	}
}

func TestSettingsGet_APIError(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "error", ErrorMessage: "denied"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if _, err := c.SettingsGet(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestSettingsSet(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/settings/set" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		checks := map[string]string{
			"dnssecValidation":  "true",
			"forwarders":        "1.1.1.1,8.8.8.8",
			"forwarderProtocol": "Tcp",
			"blockingType":      BlockingTypeCustomAddress,
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
	err := c.SettingsSet(context.Background(), map[string]string{
		"dnssecValidation":  "true",
		"forwarders":        "1.1.1.1,8.8.8.8",
		"forwarderProtocol": "Tcp",
		"blockingType":      BlockingTypeCustomAddress,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSettingsSet_APIError(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "error", ErrorMessage: "bad setting"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.SettingsSet(context.Background(), map[string]string{"x": "y"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidBlockingTypes(t *testing.T) {
	// Guard the exported constant list used for schema validation upstream.
	want := []string{
		BlockingTypeNxDomain,
		BlockingTypeAnyAddress,
		BlockingTypeTxtRecord,
		BlockingTypeCustomAddress,
	}
	if len(ValidBlockingTypes) != len(want) {
		t.Fatalf("expected %d blocking types, got %d", len(want), len(ValidBlockingTypes))
	}
	for i, v := range want {
		if ValidBlockingTypes[i] != v {
			t.Errorf("ValidBlockingTypes[%d] = %q, want %q", i, ValidBlockingTypes[i], v)
		}
	}
}
