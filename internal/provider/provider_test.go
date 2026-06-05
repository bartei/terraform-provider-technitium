// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testAccProtoV6ProviderFactories is used by acceptance tests.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"technitium": providerserver.NewProtocol6WithError(New("test")()),
}

// testAccProviderHCL returns a `provider "technitium" { ... }` HCL block
// suitable for use in acceptance test configurations. Values are taken from
// environment variables so the same test config works against either the
// default HTTP test container or the HTTPS-enabled one (`make testacc-up-tls`).
//
// Environment variables consulted:
//
//	TECHNITIUM_SERVER_URL  defaults to "http://127.0.0.1:5380"
//	TECHNITIUM_CACERT      defaults to "" (ca_cert_file omitted from the block)
//	TECHNITIUM_API_TOKEN   resolved by testAccAPIToken()
//
// Tests that need to assert on a SPECIFIC provider configuration (for example,
// to test the provider's own behavior when given an HTTP URL or a self-signed
// cert with skip_tls_verify) should NOT use this helper — they should write
// their own provider block inline.
func testAccProviderHCL() string {
	serverURL := os.Getenv("TECHNITIUM_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:5380"
	}
	caCertLine := ""
	if ca := os.Getenv("TECHNITIUM_CACERT"); ca != "" {
		caCertLine = fmt.Sprintf("\n  ca_cert_file = %q", ca)
	}
	return fmt.Sprintf(`provider "technitium" {
  server_url = %q
  api_token  = %q%s
}
`, serverURL, testAccAPIToken(), caCertLine)
}

func TestProviderSchema_NoError(t *testing.T) {
	p := New("test")()
	schemaResp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, schemaResp)

	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("provider schema returned errors: %v", schemaResp.Diagnostics)
	}

	// Verify key attributes exist
	attrs := schemaResp.Schema.Attributes
	for _, key := range []string{"server_url", "api_token", "skip_tls_verify", "ca_cert_file", "ca_cert_dir", "tls_server_name", "tls_min_version"} {
		if _, ok := attrs[key]; !ok {
			t.Errorf("expected attribute %q in provider schema", key)
		}
	}
}
