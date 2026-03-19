resource "technitium_zone" "signed" {
  name = "secure.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"
    nx_proof  = "NSEC3"
  }
}
