// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestZoneList(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/list" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status: "ok",
			Response: json.RawMessage(`{"zones":[
				{"name":"example.com","type":"Primary","disabled":false,"soaSerial":42,"dnssecStatus":"SignedWithNSEC","hasDnssecPrivateKeys":true,"lastModified":"2024-01-01"},
				{"name":"internal","type":"Primary","internal":true,"catalog":null,"dnssecStatus":"Unsigned"}
			]}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	zones, err := c.ZoneList(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}
	if zones[0].Name != "example.com" || zones[0].SOASerial != 42 || !zones[0].HasDNSSECPrivateKeys {
		t.Errorf("unexpected zone[0]: %+v", zones[0])
	}
	if !zones[1].Internal || zones[1].DNSSECStatus != "Unsigned" {
		t.Errorf("unexpected zone[1]: %+v", zones[1])
	}
}

func TestZoneOptionsGet(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/options/get" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.FormValue("zone") != "example.com" {
			t.Errorf("expected zone=example.com, got %q", r.FormValue("zone"))
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status: "ok",
			Response: json.RawMessage(`{
				"name":"example.com","type":"Primary","dnssecStatus":"SignedWithNSEC3","soaSerial":7,
				"queryAccess":"Allow","zoneTransfer":"AllowOnlyZoneNameServers",
				"zoneTransferTsigKeyNames":["key1"],"notify":"ZoneNameServers","update":"Deny"
			}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	zone, err := c.ZoneOptionsGet(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if zone.QueryAccess != "Allow" || zone.ZoneTransfer != "AllowOnlyZoneNameServers" {
		t.Errorf("unexpected access fields: %+v", zone)
	}
	if len(zone.ZoneTransferTsigKeys) != 1 || zone.ZoneTransferTsigKeys[0] != "key1" {
		t.Errorf("unexpected tsig keys: %+v", zone.ZoneTransferTsigKeys)
	}
}

func TestZoneCreate(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/create" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.FormValue("zone") != "new.example" || r.FormValue("type") != "Primary" {
			t.Errorf("unexpected params: %v", r.PostForm)
		}
		if r.FormValue("useSoaSerialDateScheme") != "true" {
			t.Errorf("expected useSoaSerialDateScheme=true, got %q", r.FormValue("useSoaSerialDateScheme"))
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:   "ok",
			Response: json.RawMessage(`{"domain":"new.example"}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	domain, err := c.ZoneCreate(context.Background(), "new.example", "Primary", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if domain != "new.example" {
		t.Errorf("expected domain new.example, got %q", domain)
	}
}

func TestZoneCreate_OmitsSoaSchemeWhenFalse(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.PostForm == nil {
			_ = r.ParseForm()
		}
		if r.PostForm.Has("useSoaSerialDateScheme") {
			t.Error("useSoaSerialDateScheme must be omitted when false")
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok", Response: json.RawMessage(`{"domain":"z"}`)}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if _, err := c.ZoneCreate(context.Background(), "z", "Primary", false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZoneDelete(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/delete" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.FormValue("zone") != "gone.example" {
			t.Errorf("expected zone=gone.example, got %q", r.FormValue("zone"))
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.ZoneDelete(context.Background(), "gone.example"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZoneDelete_APIErrorPropagates(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "error", ErrorMessage: "No such zone was found: x"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.ZoneDelete(context.Background(), "x"); err == nil {
		t.Fatal("expected error to propagate")
	}
}

func TestZoneOptionsSet(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/options/set" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.FormValue("zone") != "example.com" {
			t.Errorf("expected zone=example.com, got %q", r.FormValue("zone"))
		}
		if r.FormValue("queryAccess") != "AllowOnlyPrivateNetworks" {
			t.Errorf("unexpected queryAccess %q", r.FormValue("queryAccess"))
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	err := c.ZoneOptionsSet(context.Background(), "example.com", map[string]string{"queryAccess": "AllowOnlyPrivateNetworks"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZoneSetCatalog(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/options/set" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.FormValue("zone") != "member.example" || r.FormValue("catalog") != "cat.example" {
			t.Errorf("unexpected params: %v", r.PostForm)
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.ZoneSetCatalog(context.Background(), "member.example", "cat.example"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZoneSetCatalog_EmptyUnsets(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.PostForm == nil {
			_ = r.ParseForm()
		}
		// Empty catalog string is sent (present but empty) to clear membership.
		if !r.PostForm.Has("catalog") {
			t.Error("catalog param must be sent even when empty to unset membership")
		}
		if r.FormValue("catalog") != "" {
			t.Errorf("expected empty catalog, got %q", r.FormValue("catalog"))
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.ZoneSetCatalog(context.Background(), "member.example", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZoneDNSSECSign_NSEC3Defaults(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/dnssec/sign" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		checks := map[string]string{
			"zone":            "example.com",
			"algorithm":       "ECDSA",
			"curve":           "P256",
			"nxProof":         "NSEC3",
			"dnsKeyTtl":       "86400",
			"zskRolloverDays": "30",
			"iterations":      "0",
			"saltLength":      "0",
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
	if err := c.ZoneDNSSECSign(context.Background(), "example.com", "ECDSA", "P256", "NSEC3"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZoneDNSSECSign_NSECOmitsIterations(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.PostForm == nil {
			_ = r.ParseForm()
		}
		if r.PostForm.Has("iterations") || r.PostForm.Has("saltLength") {
			t.Error("iterations/saltLength must only be sent for NSEC3")
		}
		// EDDSA without a curve: curve must be omitted.
		if r.PostForm.Has("curve") {
			t.Error("curve must be omitted when empty")
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.ZoneDNSSECSign(context.Background(), "example.com", "EDDSA", "", "NSEC"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZoneDNSSECUnsign(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/dnssec/unsign" || r.FormValue("zone") != "example.com" {
			t.Errorf("unexpected request: %s %v", r.URL.Path, r.PostForm)
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.ZoneDNSSECUnsign(context.Background(), "example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestZoneDNSSECPropertiesGet(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/dnssec/properties/get" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status: "ok",
			Response: json.RawMessage(`{
				"name":"example.com","type":"Primary","dnssecStatus":"SignedWithNSEC3",
				"nsec3Iterations":0,"nsec3SaltLength":0,"dnsKeyTtl":86400,
				"dnssecPrivateKeys":[{"keyTag":12345,"keyType":"KeySigningKey","algorithm":"ECDSAP256SHA256","algorithmNumber":13,"state":"Ready","isRetiring":false,"rolloverDays":0}]
			}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	props, err := c.ZoneDNSSECPropertiesGet(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if props.DNSSECStatus != "SignedWithNSEC3" || props.DNSKeyTTL != 86400 {
		t.Errorf("unexpected props: %+v", props)
	}
	if len(props.DNSSECPrivateKeys) != 1 || props.DNSSECPrivateKeys[0].KeyTag != 12345 {
		t.Errorf("unexpected keys: %+v", props.DNSSECPrivateKeys)
	}
}

func TestZoneDNSSECViewDS(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/dnssec/viewDS" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status: "ok",
			Response: json.RawMessage(`{
				"name":"example.com","dnssecStatus":"SignedWithNSEC",
				"dsRecords":[{"keyTag":12345,"algorithm":"ECDSAP256SHA256","digests":[{"digestType":"SHA256","digest":"ABCD"}]}]
			}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	info, err := c.ZoneDNSSECViewDS(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.DSRecords) != 1 || info.DSRecords[0].KeyTag != 12345 {
		t.Fatalf("unexpected DS records: %+v", info.DSRecords)
	}
	if len(info.DSRecords[0].Digests) != 1 || info.DSRecords[0].Digests[0].Digest != "ABCD" {
		t.Errorf("unexpected digest: %+v", info.DSRecords[0].Digests)
	}
}

func TestZoneExists(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:   "ok",
			Response: json.RawMessage(`{"zones":[{"name":"Example.COM","type":"Primary"}]}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})

	// Case-insensitive match.
	exists, err := c.ZoneExists(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected zone to exist (case-insensitive)")
	}

	missing, err := c.ZoneExists(context.Background(), "other.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if missing {
		t.Error("expected zone to not exist")
	}
}

func TestZoneExists_ListError(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "error", ErrorMessage: "boom"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if _, err := c.ZoneExists(context.Background(), "x"); err == nil {
		t.Fatal("expected error from underlying list")
	}
}
