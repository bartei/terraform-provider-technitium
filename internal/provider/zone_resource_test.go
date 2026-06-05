// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/bartei/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccZoneResource_Primary(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read
			{
				Config: testAccZoneResourceConfig("acc-test.example.com", "Primary"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.test", "name", "acc-test.example.com"),
					resource.TestCheckResourceAttr("technitium_zone.test", "type", "Primary"),
					resource.TestCheckResourceAttr("technitium_zone.test", "status", "enabled"),
					resource.TestCheckResourceAttr("technitium_zone.test", "dnssec_status", "SignedWithNSEC3"),
				),
			},
			// Import
			{
				ResourceName:      "technitium_zone.test",
				ImportState:       true,
				ImportStateId:     "acc-test.example.com",
				ImportStateVerify: true,
				// soa_serial_date_scheme is a create-only param, can't be read back
				ImportStateVerifyIgnore: []string{"soa_serial_date_scheme", "dnssec"},
			},
		},
	})
}

func TestAccZoneResource_PrimaryNoDNSSEC(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceNoDNSSEC("acc-unsigned.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.unsigned", "name", "acc-unsigned.example.com"),
					resource.TestCheckResourceAttr("technitium_zone.unsigned", "dnssec_status", "Unsigned"),
				),
			},
		},
	})
}

func TestAccZoneDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneDataSourceConfig("acc-ds.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.technitium_zone.test", "name", "acc-ds.example.com"),
					resource.TestCheckResourceAttr("data.technitium_zone.test", "type", "Primary"),
				),
			},
		},
	})
}

func TestAccZoneResource_DNSSEC_P256(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceP256("acc-p256.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.p256", "name", "acc-p256.example.com"),
					resource.TestCheckResourceAttr("technitium_zone.p256", "dnssec_status", "SignedWithNSEC3"),
					// P256 should be preserved as configured
					resource.TestCheckResourceAttr("technitium_zone.p256", "dnssec.curve", "P256"),
				),
			},
		},
	})
}

func TestAccZoneResource_ZoneTransferTsigKeys(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceWithTsigKeys("acc-tsig-xfer.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.tsig", "name", "acc-tsig-xfer.example.com"),
					resource.TestCheckResourceAttr("technitium_zone.tsig", "zone_transfer_tsig_key_names.#", "1"),
					resource.TestCheckResourceAttr("technitium_zone.tsig", "zone_transfer_tsig_key_names.0", "acc-xfer-key.example.com"),
				),
			},
		},
	})
}

func TestAccZoneResource_ZoneTransferTsigKeys_Clear(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create zone with TSIG key
			{
				Config: testAccZoneResourceWithTsigKeys("acc-tsig-clear.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.tsig", "zone_transfer_tsig_key_names.#", "1"),
				),
			},
			// Step 2: Remove TSIG keys
			{
				Config: testAccZoneResourceNoTsigKeys("acc-tsig-clear.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.tsig", "zone_transfer_tsig_key_names.#", "0"),
				),
			},
		},
	})
}

func TestAccZoneResource_PrimaryTsigKeyOnPrimaryZone_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneResourcePrimaryTsigOnPrimary(),
				ExpectError: regexp.MustCompile(`only valid for Secondary`),
			},
		},
	})
}

func testAccZoneResourcePrimaryTsigOnPrimary() string {
	return testAccProviderHCL() + `
resource "technitium_zone" "bad" {
  name = "acc-bad-primary-tsig.example.com"
  type = "Primary"

  primary_zone_transfer_tsig_key_name = "nonexistent-key"

  dnssec {
    enabled = false
  }
}
`
}

func TestAccZoneResource_ZoneTransferTsigKeys_OnStub_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneResourceTsigKeysOnStub(),
				ExpectError: regexp.MustCompile(`only valid for Primary`),
			},
		},
	})
}

func testAccZoneResourceTsigKeysOnStub() string {
	return testAccProviderHCL() + `
resource "technitium_zone" "bad" {
  name = "acc-bad-stub-tsig.example.com"
  type = "Stub"

  zone_transfer_tsig_key_names = ["some-key"]
}
`
}

func TestAccZoneResource_TsigKeyNotFound_Rejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneResourceTsigKeyNotFound(),
				ExpectError: regexp.MustCompile(`TSIG key .* not found`),
			},
		},
	})
}

func testAccZoneResourceTsigKeyNotFound() string {
	return testAccProviderHCL() + `
resource "technitium_zone" "bad" {
  name = "acc-bad-notfound-tsig.example.com"
  type = "Primary"

  zone_transfer_tsig_key_names = ["nonexistent-key.example.com"]

  dnssec {
    enabled = false
  }
}
`
}

func testAccZoneResourceWithTsigKeys(zoneName string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_tsig_key" "xfer" {
  key_name  = "acc-xfer-key.example.com"
  algorithm = "hmac-sha256"
}

resource "technitium_zone" "tsig" {
  name = %q
  type = "Primary"

  zone_transfer_tsig_key_names = [technitium_tsig_key.xfer.key_name]

  dnssec {
    enabled = false
  }
}
`, zoneName)
}

func testAccZoneResourceNoTsigKeys(zoneName string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_tsig_key" "xfer" {
  key_name  = "acc-xfer-key.example.com"
  algorithm = "hmac-sha256"
}

resource "technitium_zone" "tsig" {
  name = %q
  type = "Primary"

  zone_transfer_tsig_key_names = []

  dnssec {
    enabled = false
  }
}
`, zoneName)
}

func testAccZoneResourceP256(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_zone" "p256" {
  name = %q
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"
    nx_proof  = "NSEC3"
  }
}
`, name)
}

func testAccZoneResourceConfig(name, zoneType string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_zone" "test" {
  name = %q
  type = %q

  soa_serial_date_scheme = true

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"
    nx_proof  = "NSEC3"
  }
}
`, name, zoneType)
}

func testAccZoneResourceNoDNSSEC(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_zone" "unsigned" {
  name = %q
  type = "Primary"

  dnssec {
    enabled = false
  }
}
`, name)
}

func testAccZoneDataSourceConfig(name string) string {
	return testAccProviderHCL() + fmt.Sprintf(`
resource "technitium_zone" "seed" {
  name = %q
  type = "Primary"

  dnssec {
    enabled = false
  }
}

data "technitium_zone" "test" {
  name = technitium_zone.seed.name
}
`, name)
}

// testAccDirectClient creates a direct API client for test setup operations
// that need to bypass Terraform resource lifecycle.
func testAccDirectClient(t *testing.T) *client.Client {
	t.Helper()
	// Same gate as resource.Test: callers use this helper for pre-test setup
	// against a live server, which must not run during offline unit tests.
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}
	c, err := client.NewClient(client.ClientConfig{BaseURL: "http://127.0.0.1:5380", Token: testAccAPIToken()})
	if err != nil {
		t.Fatalf("failed to create direct API client: %s", err)
	}
	return c
}

func testAccAPIToken() string {
	// Read from environment — token is provisioned when the Docker test
	// instance starts (make testacc-token / testacc-token-tls).
	token := os.Getenv("TECHNITIUM_API_TOKEN")
	if token == "" && os.Getenv("TF_ACC") != "" {
		// This helper is called from HCL config builders that have no
		// *testing.T, so it cannot t.Skip. An armed acceptance run without
		// a token is a harness misconfiguration: fail fast and loud rather
		// than letting every test fail with confusing auth errors.
		panic("TF_ACC is set but TECHNITIUM_API_TOKEN is empty; run `make testacc-up` or `make testacc-up-tls` to provision a token")
	}
	return token
}
