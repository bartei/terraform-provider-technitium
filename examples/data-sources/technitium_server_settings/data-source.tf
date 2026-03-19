data "technitium_server_settings" "current" {}

output "server_version" {
  value = data.technitium_server_settings.current.version
}

output "dnssec_enabled" {
  value = data.technitium_server_settings.current.dnssec_validation
}
