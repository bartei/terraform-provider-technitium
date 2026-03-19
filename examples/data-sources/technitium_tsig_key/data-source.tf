data "technitium_tsig_key" "transfer" {
  key_name = "transfer.example.com"
}

resource "technitium_zone" "secondary" {
  name = "example.com"
  type = "Secondary"

  primary_zone_transfer_tsig_key_name = data.technitium_tsig_key.transfer.key_name
}
