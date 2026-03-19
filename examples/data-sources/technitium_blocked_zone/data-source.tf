data "technitium_blocked_zone" "check" {
  domain = "ads.example.com"
}

output "is_blocked" {
  value = data.technitium_blocked_zone.check.exists
}
