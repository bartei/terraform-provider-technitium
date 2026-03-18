// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure TechnitiumProvider satisfies various provider interfaces.
var _ provider.Provider = &TechnitiumProvider{}

// TechnitiumProvider defines the provider implementation.
type TechnitiumProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &TechnitiumProvider{
			version: version,
		}
	}
}

func (p *TechnitiumProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "technitium"
	resp.Version = p.version
}

func (p *TechnitiumProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform provider for managing Technitium DNS Server. " +
			"Provides STIG-hardened defaults and optional CNSSI 1253 compliance enforcement.",
		Attributes: map[string]schema.Attribute{
			// TODO: Implement provider schema attributes (Phase 1)
			// - server_url
			// - api_token
			// - skip_tls_verify
			// - stig_compliance block
		},
	}
}

func (p *TechnitiumProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
	// TODO: Implement provider configuration (Phase 1)
	// - Read server_url, api_token, skip_tls_verify
	// - Initialize HTTP client
	// - Parse STIG compliance settings
	// - Store in ProviderData struct
}

func (p *TechnitiumProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		// TODO: Register resources as they are implemented
		// Phase 1: NewZoneResource
		// Phase 2: NewRecordResource
		// Phase 3: NewServerSettingsResource
		// Phase 4: NewTSIGKeyResource
	}
}

func (p *TechnitiumProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		// TODO: Register data sources as they are implemented
		// Phase 1: NewZoneDataSource
		// Phase 2: NewRecordDataSource
		// Phase 3: NewServerSettingsDataSource
	}
}
