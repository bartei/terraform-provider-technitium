resource "technitium_server_settings" "main" {
  dnssec_validation = true
  recursion         = "AllowOnlyForPrivateNetworks"
  log_queries       = true
}
