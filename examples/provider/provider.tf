terraform {
  required_providers {
    technitium = {
      source = "registry.terraform.io/bartei/technitium"
    }
  }
}

provider "technitium" {
  server_url = var.technitium_server_url
  api_token  = var.technitium_api_token
}

variable "technitium_server_url" {
  description = "Technitium DNS Server URL"
  type        = string
  default     = "http://127.0.0.1:5380"
}

variable "technitium_api_token" {
  description = "Technitium API token"
  type        = string
  sensitive   = true
}
