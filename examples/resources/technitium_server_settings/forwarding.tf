resource "technitium_server_settings" "forwarding" {
  forwarders         = ["1.1.1.1", "8.8.8.8"]
  forwarder_protocol = "Tls"
  recursion          = "AllowOnlyForPrivateNetworks"

  serve_stale      = true
  udp_payload_size = 1232
}
