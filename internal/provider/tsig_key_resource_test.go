// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccTSIGKeyResource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTSIGKeyResourceBasic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("technitium_tsig_key.test", "key_name", "acc-basic.example.com"),
					resource.TestCheckResourceAttr("technitium_tsig_key.test", "algorithm", "hmac-sha256"),
					resource.TestCheckResourceAttrSet("technitium_tsig_key.test", "shared_secret"),
					resource.TestCheckResourceAttr("technitium_tsig_key.test", "id", "acc-basic.example.com"),
				),
			},
			{
				ResourceName:            "technitium_tsig_key.test",
				ImportState:             true,
				ImportStateId:           "acc-basic.example.com",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"shared_secret"},
			},
		},
	})
}

func testAccTSIGKeyResourceBasic() string {
	return fmt.Sprintf(`
provider "technitium" {
  server_url = "http://127.0.0.1:5380"
  api_token  = "%s"
}

resource "technitium_tsig_key" "test" {
  key_name      = "acc-basic.example.com"
  algorithm     = "hmac-sha256"
  shared_secret = "dGVzdHNlY3JldGtleWZvcmFjY2VwdGFuY2V0ZXN0cw=="
}
`, testAccAPIToken())
}
