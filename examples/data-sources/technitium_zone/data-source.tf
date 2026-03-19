data "technitium_zone" "example" {
  name = "example.com"
}

output "zone_dnssec_status" {
  value = data.technitium_zone.example.dnssec_status
}
