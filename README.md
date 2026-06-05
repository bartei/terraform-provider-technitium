# Terraform Provider for Technitium DNS Server

[![Terraform Registry](https://img.shields.io/badge/terraform-registry-blueviolet)](https://registry.terraform.io/providers/bartei/technitium/latest)
[![Go Version](https://img.shields.io/badge/go-1.26-blue)](https://go.dev/)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-orange)](LICENSE)

## Overview

[Technitium DNS Server](https://technitium.com/dns/) is an open-source, cross-platform,
self-hosted DNS server with a full-featured web console. It supports authoritative zones,
recursive resolution, DNSSEC, DNS-over-HTTPS/TLS, blocking, and much more — making it an
excellent choice for production DNS infrastructure.

This provider enables you to manage Technitium DNS Server infrastructure entirely as code
through Terraform. Define zones, records, TSIG keys, DNSSEC configuration, catalog zone
membership, and server-wide settings in declarative HCL, then plan, review, and apply
changes with the same workflow you use for every other piece of your infrastructure.

## Features

- DNS zone management (Primary, Secondary, Stub, Forwarder)
- DNS record management (A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, CAA) with multi-record support for round-robin, multiple MX exchanges, and other multi-value configurations
- DNSSEC signing configuration
- TSIG key management for authenticated zone transfers
- **Catalog zone membership ([RFC 9432](https://datatracker.ietf.org/doc/rfc9432/)) for multi-server deployments**
- Server-wide DNS settings
- Domain blocking and allowing
- TLS configuration with custom CA support and environment variable fallbacks
- Client-side DNS record input validation

## Quick Start

```hcl
terraform {
  required_providers {
    technitium = {
      source  = "bartei/technitium"
      version = "~> 1.2"
    }
  }
}

provider "technitium" {
  server_url = "http://192.168.1.10:5380"
  api_token  = var.technitium_api_token
}

resource "technitium_zone" "homelab" {
  name = "home.lan"
  type = "Primary"
}

resource "technitium_record" "nas" {
  zone  = technitium_zone.homelab.name
  name  = "nas.home.lan"
  type  = "A"
  value = "192.168.1.50"
}
```

### Hardened deployment

HTTPS-enabled Technitium with a custom CA for an internal PKI:

```hcl
provider "technitium" {
  server_url = "https://dns.example.com"
  api_token  = var.technitium_api_token

  ca_cert_file    = "/etc/ssl/certs/internal-ca.pem"
  tls_server_name = "dns.example.com"
  tls_min_version = "1.3"
}

resource "technitium_zone" "example" {
  name           = "example.com"
  type           = "Primary"
  notify         = ["10.0.0.2"]
  allow_transfer = ["10.0.0.0/8"]

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P384"
    nx_proof  = "NSEC3"
  }
}

resource "technitium_record" "web" {
  zone  = technitium_zone.example.name
  name  = "www.example.com"
  type  = "A"
  value = "192.168.1.100"
}
```

### Multi-record support

Multiple records at the same name and type are fully supported — set `overwrite = false`
to manage individual records within an RRset:

```hcl
resource "technitium_record" "web1" {
  zone      = technitium_zone.example.name
  name      = "www.example.com"
  type      = "A"
  value     = "192.168.1.100"
  overwrite = false
}

resource "technitium_record" "web2" {
  zone      = technitium_zone.example.name
  name      = "www.example.com"
  type      = "A"
  value     = "192.168.1.101"
  overwrite = false
}
```

### Environment variable fallback

The provider can also be configured using environment variables:

```bash
export TECHNITIUM_SERVER_URL="https://dns.example.com"
export TECHNITIUM_API_TOKEN="your-api-token"
```

## Why this provider vs. the generic `hashicorp/dns` provider?

Both providers can add DNS records to Technitium, but they take fundamentally different
paths. `hashicorp/dns` speaks generic [RFC 2136](https://datatracker.ietf.org/doc/rfc2136/)
dynamic updates over TSIG — the same protocol Bind 9 uses — and works against any
DNS server that supports it. `bartei/technitium` talks directly to Technitium's
native HTTP API and exposes the full administrative surface, not just the records subset.

| Capability | `hashicorp/dns` (v3.6.1) | `bartei/technitium` |
|---|---|---|
| Manage DNS records | yes (8 `*_record*` resources) | yes (`technitium_record`) |
| Create + configure zones | no (zones must exist on the DNS server first) | yes (`technitium_zone`) |
| DNSSEC configuration | no | yes (algorithm, curve, NSEC3) |
| TSIG key lifecycle on the server | no (server-side key configured manually) | yes (`technitium_tsig_key`) |
| Catalog zone membership ([RFC 9432](https://datatracker.ietf.org/doc/rfc9432/)) | no | yes (`technitium_catalog_membership`) |
| Server-wide settings (blocking, forwarding) | no | yes (`technitium_server_settings`) |
| Authentication | TSIG ([RFC 2845](https://datatracker.ietf.org/doc/rfc2845/)) shared secret, OR GSS-TSIG ([RFC 3645](https://datatracker.ietf.org/doc/rfc3645/)) for Kerberos / Active Directory | Per-user API token (revocable, scoped) |
| Provider-to-server transport | UDP/TCP on port 53 | HTTPS (REST API) |

**Where `hashicorp/dns` is the better fit:** Active-Directory-integrated environments
where GSS-TSIG / Kerberos authentication is the natural choice, or mixed-DNS-server
environments where standard RFC 2136 compatibility across multiple vendors matters
more than Technitium-specific features. This provider does not implement Kerberos
authentication.

**Where this provider is the better fit:** Technitium-only deployments where you want
end-to-end management — zones, DNSSEC posture, TSIG keys, catalog membership, server
settings, blocking, and the records themselves — in one declarative configuration.

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
      source  = "bartei/technitium"
      version = "~> 1.2"
    }
  }
}
```

Then run `terraform init`.

### Local Development

Clone the repository and install the provider binary into your local plugin directory:

```bash
git clone https://github.com/bartei/terraform-provider-technitium.git
cd terraform-provider-technitium
make install
```

## Documentation

- [Terraform Registry Documentation](https://registry.terraform.io/providers/bartei/technitium/latest/docs)
- [Changelog](CHANGELOG.md)

## Development

### Building

```bash
git clone https://github.com/bartei/terraform-provider-technitium.git
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

> **Note:** Acceptance tests require a running Technitium DNS Server instance. The
> `make testacc-up` target handles the full lifecycle: runs a preflight ownership
> check on `./.testdata/`, creates the bind-mount data directory with host-user
> ownership, starts the container as a non-root user (per issue #36), provisions a
> fresh API token, and runs every acceptance test. Unit tests (`make test`) do not
> require Docker and run entirely offline.
>
> Invoking `docker compose -f docker-compose.test.yml up -d` directly is **not
> supported**. The compose file's `user:` directive expects `HOST_UID` and
> `HOST_GID` environment variables exported by the make target, and the bind-mount
> source directory must exist with the host user's ownership before container
> start. Bypassing `make` will silently fall back to `1000:1000` and may produce
> permission errors on any host where the user's UID/GID differs.

#### TLS-mode acceptance suite

The default `make testacc-up` runs the Technitium container with HTTP only on port `5380`.
The parallel `testacc-up-tls` target boots an HTTPS-enabled container and runs the full
test suite against it:

```bash
make testacc-up-tls   # generate fresh CA + server cert, boot HTTPS container, run all tests
make testacc-down-tls # tear down the HTTPS container when finished
```

The TLS variant generates a fresh ECDSA P-384 self-signed CA and server certificate into
`./testdata/tls/` (gitignored), packages the server credentials as a PKCS#12 bundle,
mounts them into the Technitium container at `/etc/dns/tls/server.pfx`, and exposes the
admin web service on `127.0.0.1:5443` over HTTPS. The provider trusts the test CA via the
`TECHNITIUM_CACERT` environment variable. No private key material is ever committed.

The TLS target sources `DNS_ADMIN_PASSWORD` from `.env.test` (falling back to `admin` to
match `.env.test.example`). It does not require any production credential.

> **Credential handling:** the make targets read `DNS_ADMIN_PASSWORD` from `.env.test`
> into a shell variable and pipe it to `scripts/test-token-bootstrap.sh` on stdin via a
> shell-builtin `printf`. The script reads the password from stdin into a local shell
> variable, never sees it via argv or env, URL-encodes it through a python helper that
> also reads from stdin, and sends the form body to curl via `--data @-` on a bash
> heredoc. The credential value therefore does not appear in `/proc/PID/cmdline`
> (`ps -ef`) or `/proc/PID/environ` (`ps eww`) of any process spawned during token
> provisioning.

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
