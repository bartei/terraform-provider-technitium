// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccRecordResource_A(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create
			{
				Config: testAccRecordA("rec-a-test.example.com", "www.rec-a-test.example.com", "192.0.2.10"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.web", "name", "www.rec-a-test.example.com"),
					resource.TestCheckResourceAttr("technitium_record.web", "type", "A"),
					resource.TestCheckResourceAttr("technitium_record.web", "value", "192.0.2.10"),
					resource.TestCheckResourceAttr("technitium_record.web", "ttl", "3600"),
				),
			},
			// Update value
			{
				Config: testAccRecordA("rec-a-test.example.com", "www.rec-a-test.example.com", "192.0.2.20"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.web", "value", "192.0.2.20"),
				),
			},
			// Import
			{
				ResourceName:            "technitium_record.web",
				ImportState:             true,
				ImportStateId:           "rec-a-test.example.com/www.rec-a-test.example.com/A",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"overwrite"},
			},
		},
	})
}

func TestAccRecordResource_CNAME(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordCNAME("rec-cname-test.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.alias", "type", "CNAME"),
					resource.TestCheckResourceAttr("technitium_record.alias", "value", "rec-cname-test.example.com"),
				),
			},
		},
	})
}

func TestAccRecordResource_TXT(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordTXT("rec-txt-test.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_record.spf", "type", "TXT"),
					resource.TestCheckResourceAttr("technitium_record.spf", "value", "v=spf1 -all"),
				),
			},
		},
	})
}

func TestAccRecordDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRecordDataSource("rec-ds-test.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.technitium_record.web", "value", "192.0.2.100"),
					resource.TestCheckResourceAttr("data.technitium_record.web", "ttl", "3600"),
				),
			},
		},
	})
}

func testAccRecordA(zone, name, ip string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "web" {
  zone  = technitium_zone.test.name
  name  = %q
  type  = "A"
  ttl   = 3600
  value = %q
}
`, testAccAPIToken(), zone, name, ip)
}

func testAccRecordCNAME(zone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "alias" {
  zone  = technitium_zone.test.name
  name  = "www.%s"
  type  = "CNAME"
  value = %q
}
`, testAccAPIToken(), zone, zone, zone)
}

func testAccRecordTXT(zone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "spf" {
  zone  = technitium_zone.test.name
  name  = %q
  type  = "TXT"
  value = "v=spf1 -all"
}
`, testAccAPIToken(), zone, zone)
}

func testAccRecordDataSource(zone string) string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "seed" {
  zone  = technitium_zone.test.name
  name  = "www.%s"
  type  = "A"
  value = "192.0.2.100"
}

data "technitium_record" "web" {
  zone = technitium_zone.test.name
  name = technitium_record.seed.name
  type = "A"
}
`, testAccAPIToken(), zone, zone)
}
