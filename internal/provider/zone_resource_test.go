// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

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

func TestAccZoneResource_NSSRejectsP256(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccZoneResourceNSSP256("acc-nss-reject.example.com"),
				ExpectError: regexp.MustCompile(`P256 not allowed in NSS mode`),
			},
		},
	})
}

func TestAccZoneResource_NSSAcceptsP384(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceNSSP384("acc-nss-p384.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.nss", "name", "acc-nss-p384.example.com"),
					resource.TestCheckResourceAttr("technitium_zone.nss", "dnssec_status", "SignedWithNSEC3"),
					resource.TestCheckResourceAttr("technitium_zone.nss", "dnssec.curve", "P384"),
				),
			},
		},
	})
}

func TestAccZoneResource_NonNSSKeepsP256(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccZoneResourceNonNSSP256("acc-nonnss.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_zone.nonnss", "name", "acc-nonnss.example.com"),
					resource.TestCheckResourceAttr("technitium_zone.nonnss", "dnssec_status", "SignedWithNSEC3"),
					// Without NSS, P256 should stay P256
					resource.TestCheckResourceAttr("technitium_zone.nonnss", "dnssec.curve", "P256"),
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
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "bad" {
  name = "acc-bad-primary-tsig.example.com"
  type = "Primary"

  primary_zone_transfer_tsig_key_name = "nonexistent-key"

  dnssec {
    enabled = false
  }
}
`, testAccAPIToken())
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
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "bad" {
  name = "acc-bad-stub-tsig.example.com"
  type = "Stub"

  zone_transfer_tsig_key_names = ["some-key"]
}
`, testAccAPIToken())
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
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "bad" {
  name = "acc-bad-notfound-tsig.example.com"
  type = "Primary"

  zone_transfer_tsig_key_names = ["nonexistent-key.example.com"]

  dnssec {
    enabled = false
  }
}
`, testAccAPIToken())
}

func testAccZoneResourceWithTsigKeys(zoneName string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

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
`, testAccAPIToken(), zoneName)
}

func testAccZoneResourceNSSP256(name string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"

  stig_compliance {
    enabled = true
    nss     = true

    categorization {
      confidentiality = "high"
      integrity       = "high"
      availability    = "moderate"
    }
  }
}

resource "technitium_zone" "nss" {
  name = %q
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"
    nx_proof  = "NSEC3"
  }
}
`, testAccAPIToken(), name)
}

func testAccZoneResourceNSSP384(name string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"

  stig_compliance {
    enabled = true
    nss     = true

    categorization {
      confidentiality = "high"
      integrity       = "high"
      availability    = "moderate"
    }
  }
}

resource "technitium_zone" "nss" {
  name = %q
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P384"
    nx_proof  = "NSEC3"
  }
}
`, testAccAPIToken(), name)
}

func testAccZoneResourceNonNSSP256(name string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "nonnss" {
  name = %q
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"
    nx_proof  = "NSEC3"
  }
}
`, testAccAPIToken(), name)
}

func testAccZoneResourceConfig(name, zoneType string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

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
`, testAccAPIToken(), name, zoneType)
}

func testAccZoneResourceNoDNSSEC(name string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "unsigned" {
  name = %q
  type = "Primary"

  dnssec {
    enabled = false
  }
}
`, testAccAPIToken(), name)
}

func testAccZoneDataSourceConfig(name string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

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
`, testAccAPIToken(), name)
}

func testAccAPIToken() string {
	// Read from environment — token is provisioned when the Docker test instance starts.
	// Set via .env.test or TECHNITIUM_API_TOKEN env var.
	token := os.Getenv("TECHNITIUM_API_TOKEN")
	if token == "" {
		// Fallback for CI or manual runs
		token = "7b34e85a6f9bdf8dacf8513024463408c51980663e47c1cd522f2f9071686388"
	}
	return token
}
