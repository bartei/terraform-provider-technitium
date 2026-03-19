resource "technitium_server_settings" "nss" {
  # DNS Resolution — locked down for classified environments
  dnssec_validation  = true
  recursion          = "Deny"
  qname_minimization = true
  randomize_name     = true

  # Logging — maximum retention
  log_queries       = true
  logging_type      = "FileAndConsole"
  max_log_file_days = 365

  # Forwarding — US government-controlled resolvers only
  forwarders         = var.approved_forwarders
  forwarder_protocol = "Tls"

  # Encrypted transport
  enable_dns_over_tls   = true
  enable_dns_over_https = true

  # Strict zone transfer controls
  zone_transfer_allowed_networks = var.authorized_networks
  notify_allowed_networks        = var.authorized_networks
}
