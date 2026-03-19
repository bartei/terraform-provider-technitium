data "technitium_blocked_zones" "all" {}

output "blocked_domain_count" {
  value = length(data.technitium_blocked_zones.all.domains)
}
