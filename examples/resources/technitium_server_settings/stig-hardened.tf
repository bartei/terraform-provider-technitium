resource "technitium_server_settings" "stig" {
  # DNS Resolution (DNS-REQ-005, DNS-REQ-006, DNS-REQ-014, DNS-REQ-015)
  dnssec_validation  = true
  recursion          = "AllowOnlyForPrivateNetworks"
  qname_minimization = true
  randomize_name     = true

  # Logging (DNS-REQ-007, DNS-REQ-008, DNS-REQ-009, DNS-REQ-010)
  log_queries       = true
  logging_type      = "FileAndConsole"
  max_log_file_days = 365

  # Forwarding (DNS-REQ-013, DNS-REQ-028)
  forwarders         = ["9.9.9.9", "149.112.112.112"]
  forwarder_protocol = "Tls"

  # Encrypted transport (SC-8)
  enable_dns_over_tls   = true
  enable_dns_over_https = true

  # Zone Transfer ACL (DNS-REQ-004)
  zone_transfer_allowed_networks = ["10.0.0.0/8"]
}
