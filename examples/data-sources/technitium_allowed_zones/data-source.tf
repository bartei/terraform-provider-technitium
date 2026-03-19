data "technitium_allowed_zones" "all" {}

output "allowed_domain_count" {
  value = length(data.technitium_allowed_zones.all.domains)
}
