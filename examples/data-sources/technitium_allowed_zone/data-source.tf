data "technitium_allowed_zone" "check" {
  domain = "trusted.example.com"
}

output "is_allowed" {
  value = data.technitium_allowed_zone.check.exists
}
