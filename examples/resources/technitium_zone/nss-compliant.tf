resource "technitium_tsig_key" "nss_transfer" {
  key_name  = "nss-transfer.example.mil"
  algorithm = "hmac-sha384"
}

resource "technitium_zone" "nss" {
  name = "example.mil"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P384"
    nx_proof  = "NSEC3"
  }

  zone_transfer_tsig_key_names = [
    technitium_tsig_key.nss_transfer.key_name,
  ]

  notify         = ["10.0.1.2", "10.0.1.3"]
  allow_transfer = ["10.0.1.2", "10.0.1.3"]
}
