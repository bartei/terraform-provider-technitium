# Terraform Provider for Technitium DNS Server

[![Terraform Registry](https://img.shields.io/badge/terraform-registry-blueviolet)](https://registry.terraform.io/providers/darkhonor/technitium/latest)
[![Go Version](https://img.shields.io/badge/go-1.26-blue)](https://go.dev/)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-orange)](LICENSE)

## Overview

[Technitium DNS Server](https://technitium.com/dns/) is an open-source, cross-platform,
self-hosted DNS server with a full-featured web console. It supports authoritative zones,
recursive resolution, DNSSEC, DNS-over-HTTPS/TLS, blocking, and much more — making it an
excellent choice for production DNS infrastructure.

This provider enables you to manage Technitium DNS Server infrastructure entirely as code
through Terraform. Define zones, records, TSIG keys, DNSSEC configuration, and server-wide
settings in declarative HCL, then plan, review, and apply changes with the same workflow you
use for every other piece of your infrastructure.

What sets this provider apart is its embedded [DISA STIG](https://www.cyber.mil/stigs)
compliance validation with full [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800-53/r5/upd1/final)
traceability. Twenty-eight DNS security requirements — derived from the BIND 9.x STIG V3R1
(2025-07-14) and Windows Server 2022 DNS STIG V2R3 (2025-04-02) — are evaluated at
`terraform validate` and `terraform plan` time, catching misconfigurations before they
reach your DNS server.

## Features

- DNS zone management (Primary, Secondary, Stub, Forwarder)
- DNS record management (A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, CAA)
- DNSSEC signing configuration
- TSIG key management for authenticated zone transfers
- Server-wide DNS settings
- Domain blocking and allowing
- Built-in DISA STIG compliance validation (28 DNS security requirements)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800-53/r5/upd1/final) control traceability and baseline categorization
- NSS/[CNSSI 1253](https://www.cnss.gov/CNSS/issuances/Instructions.cfm) support for classified environments
- Vault-style TLS configuration with environment variable support
- Client-side DNS record input validation

## Quick Start

Configure the provider, create a zone, and add a record:

```hcl
terraform {
  required_providers {
    technitium = {
      source  = "darkhonor/technitium"
      version = "~> 1.0"
    }
  }
}

provider "technitium" {
  server_url = "https://dns.example.com"
  api_token  = var.technitium_api_token
}

resource "technitium_zone" "example" {
  name = "example.com"
  type = "Primary"
}

resource "technitium_record" "web" {
  zone  = technitium_zone.example.name
  name  = "www.example.com"
  type  = "A"
  value = "192.168.1.100"
}
```

The provider can also be configured using environment variables:

```bash
export TECHNITIUM_SERVER_URL="https://dns.example.com"
export TECHNITIUM_API_TOKEN="your-api-token"
```

For TLS, the provider supports Vault-style configuration:

```hcl
provider "technitium" {
  server_url = "https://dns.example.com"
  api_token  = var.technitium_api_token

  tls_ca_file     = "/etc/ssl/certs/ca.pem"
  tls_client_cert = "/etc/ssl/certs/client.pem"
  tls_client_key  = "/etc/ssl/private/client-key.pem"
  skip_tls_verify = false
}
```

## STIG Compliance

This provider embeds 28 DNS security requirements derived from DISA STIGs and validates
them at `terraform validate` and `terraform plan` time — no external tools or post-hoc
scanning required. Every finding includes the STIG Rule ID, severity, and mapped
NIST SP 800-53 Rev. 5 control for full audit traceability.

Three enforcement modes are available:

| Mode | Behavior |
|---|---|
| **strict** (default) | Errors block `terraform apply` |
| **warn** | Warnings appear in plan output but do not block |
| **silent** | All STIG diagnostics suppressed |

For classified environments, NSS mode maps controls to
[CNSSI 1253](https://www.cnss.gov/CNSS/issuances/Instructions.cfm) baselines (Low,
Moderate, High) and enforces only the requirements applicable to the selected
categorization level.

For full details, see the [STIG Compliance Guide](docs/guides/stig-compliance.md) and
the [DISA STIG Library](https://www.cyber.mil/stigs).

## Requirements

| Requirement | Version |
|---|---|
| [Terraform](https://www.terraform.io/downloads.html) | >= 1.0 |
| [Go](https://go.dev/dl/) (for building) | >= 1.26 |
| [Technitium DNS Server](https://technitium.com/dns/) | >= 13.x |

## Installation

### Terraform Registry (recommended)

```hcl
terraform {
  required_providers {
    technitium = {
      source  = "darkhonor/technitium"
      version = "~> 1.0"
    }
  }
}
```

Then run `terraform init`.

### Local Development

Clone the repository and install the provider binary into your local plugin directory:

```bash
git clone https://github.com/darkhonor/terraform-provider-technitium.git
cd terraform-provider-technitium
make install
```

## Documentation

- [Terraform Registry Documentation](https://registry.terraform.io/providers/darkhonor/technitium/latest/docs)
- [STIG Compliance Guide](docs/guides/stig-compliance.md)

## Development

### Building

```bash
git clone https://github.com/darkhonor/terraform-provider-technitium.git
cd terraform-provider-technitium
make build
```

### Testing

Run unit tests:

```bash
make test
```

Run the full acceptance test suite (requires Docker):

```bash
make testacc-up
```

This starts a Technitium DNS Server container, provisions a fresh API token, and runs every
acceptance test. The container stays running so you can iterate. Tear it down when finished:

```bash
make testacc-down
```

### FIPS Build

Build with BoringCrypto for FIPS 140-2 compliance:

```bash
make build-fips
```

FIPS-mode tests are also available:

```bash
make test-fips
```

### Generating Documentation

Registry-format documentation is generated with
[tfplugindocs](https://github.com/hashicorp/terraform-plugin-docs):

```bash
make docs
```

### Linting

```bash
make lint
```

## License

MPL-2.0. See [LICENSE](LICENSE).
