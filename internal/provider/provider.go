// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

// TechnitiumProviderModel maps provider schema to Go types.
type TechnitiumProviderModel struct {
	ServerURL      types.String         `tfsdk:"server_url"`
	APIToken       types.String         `tfsdk:"api_token"`
	SkipTLSVerify  types.Bool           `tfsdk:"skip_tls_verify"`
	STIGCompliance *STIGComplianceModel `tfsdk:"stig_compliance"`
}

// STIGComplianceModel maps the stig_compliance block.
type STIGComplianceModel struct {
	Enabled        types.Bool           `tfsdk:"enabled"`
	NSS            types.Bool           `tfsdk:"nss"`
	Categorization *CategorizationModel `tfsdk:"categorization"`
}

// CategorizationModel maps the categorization block.
type CategorizationModel struct {
	Baseline        types.String `tfsdk:"baseline"`
	Confidentiality types.String `tfsdk:"confidentiality"`
	Integrity       types.String `tfsdk:"integrity"`
	Availability    types.String `tfsdk:"availability"`
}

// TechnitiumProviderData is passed to resources via req.ProviderData.
type TechnitiumProviderData struct {
	Client         *client.Client
	STIGEnabled    bool
	NSS            bool
	Categorization Categorization
}

// Categorization holds the resolved C/I/A levels.
type Categorization struct {
	Confidentiality string
	Integrity       string
	Availability    string
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
			"server_url": schema.StringAttribute{
				Description: "Technitium DNS Server API base URL. Can also be set via TECHNITIUM_SERVER_URL env var.",
				Required:    true,
			},
			"api_token": schema.StringAttribute{
				Description: "Technitium API token. Can also be set via TECHNITIUM_API_TOKEN env var.",
				Required:    true,
				Sensitive:   true,
			},
			"skip_tls_verify": schema.BoolAttribute{
				Description: "Skip TLS certificate verification. Generates STIG warning when stig_compliance is enabled (SC-8).",
				Optional:    true,
			},
		},
		Blocks: map[string]schema.Block{
			"stig_compliance": schema.SingleNestedBlock{
				Description: "STIG compliance configuration with optional CNSSI 1253 categorization.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Description: "Enable STIG validation on all resources.",
						Optional:    true,
					},
					"nss": schema.BoolAttribute{
						Description: "National Security System mode — requires full CNSSI 1253 categorization.",
						Optional:    true,
					},
				},
				Blocks: map[string]schema.Block{
					"categorization": schema.SingleNestedBlock{
						Description: "Security categorization for STIG validation.",
						Attributes: map[string]schema.Attribute{
							"baseline": schema.StringAttribute{
								Description: "Shorthand baseline: low, moderate, high. Only when nss = false. Mutually exclusive with individual objectives.",
								Optional:    true,
							},
							"confidentiality": schema.StringAttribute{
								Description: "Confidentiality objective level: low, moderate, high. Required when nss = true.",
								Optional:    true,
							},
							"integrity": schema.StringAttribute{
								Description: "Integrity objective level: low, moderate, high. Required when nss = true.",
								Optional:    true,
							},
							"availability": schema.StringAttribute{
								Description: "Availability objective level: low, moderate, high. Required when nss = true.",
								Optional:    true,
							},
						},
					},
				},
			},
		},
	}
}

func (p *TechnitiumProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config TechnitiumProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Env var fallbacks
	serverURL := config.ServerURL.ValueString()
	if serverURL == "" {
		serverURL = os.Getenv("TECHNITIUM_SERVER_URL")
	}
	if serverURL == "" {
		resp.Diagnostics.AddError("Missing server_url",
			"server_url must be set in the provider configuration or via TECHNITIUM_SERVER_URL environment variable.")
		return
	}

	apiToken := config.APIToken.ValueString()
	if apiToken == "" {
		apiToken = os.Getenv("TECHNITIUM_API_TOKEN")
	}
	if apiToken == "" {
		resp.Diagnostics.AddError("Missing api_token",
			"api_token must be set in the provider configuration or via TECHNITIUM_API_TOKEN environment variable.")
		return
	}

	skipTLSVerify := false
	if !config.SkipTLSVerify.IsNull() {
		skipTLSVerify = config.SkipTLSVerify.ValueBool()
	}

	// Create API client
	apiClient, err := client.NewClient(serverURL, apiToken, skipTLSVerify)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create API client", err.Error())
		return
	}

	// Verify connectivity
	if err := apiClient.Ping(); err != nil {
		resp.Diagnostics.AddError("Failed to connect to Technitium DNS Server",
			fmt.Sprintf("Could not reach %s: %s", serverURL, err.Error()))
		return
	}

	// Parse STIG compliance
	providerData := &TechnitiumProviderData{
		Client: apiClient,
	}

	if config.STIGCompliance != nil {
		providerData.STIGEnabled = config.STIGCompliance.Enabled.ValueBool()
		providerData.NSS = config.STIGCompliance.NSS.ValueBool()

		if config.STIGCompliance.Categorization != nil {
			cat, diags := validateCategorization(config.STIGCompliance.Categorization, providerData.NSS)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}
			providerData.Categorization = cat
		} else if providerData.NSS {
			resp.Diagnostics.AddError("Missing categorization",
				"categorization block is required when nss = true.")
			return
		}

		// STIG warning for skip_tls_verify
		if providerData.STIGEnabled && skipTLSVerify {
			resp.Diagnostics.AddWarning("STIG SC-8: TLS verification disabled",
				"skip_tls_verify = true disables TLS certificate verification. "+
					"This violates STIG requirement SC-8 (Transmission Confidentiality and Integrity).")
		}
	}

	resp.DataSourceData = providerData
	resp.ResourceData = providerData
}

func (p *TechnitiumProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewZoneResource,
		NewRecordResource,
		// TODO: Phase 3: NewServerSettingsResource
		// TODO: Phase 4: NewTSIGKeyResource
	}
}

func (p *TechnitiumProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewZoneDataSource,
		NewRecordDataSource,
		// TODO: Phase 3: NewServerSettingsDataSource
	}
}

// validLevels are the allowed CNSSI 1253 / NIST 800-53 categorization levels.
var validLevels = map[string]bool{
	"low":      true,
	"moderate": true,
	"high":     true,
}

// validateCategorization enforces the categorization rules from the design spec Section 3.
func validateCategorization(cat *CategorizationModel, nss bool) (Categorization, diag.Diagnostics) {
	var diags diag.Diagnostics
	result := Categorization{}

	hasBaseline := !cat.Baseline.IsNull() && cat.Baseline.ValueString() != ""
	hasConf := !cat.Confidentiality.IsNull() && cat.Confidentiality.ValueString() != ""
	hasInteg := !cat.Integrity.IsNull() && cat.Integrity.ValueString() != ""
	hasAvail := !cat.Availability.IsNull() && cat.Availability.ValueString() != ""
	hasIndividual := hasConf || hasInteg || hasAvail

	// Rule: baseline and individual objectives are mutually exclusive
	if hasBaseline && hasIndividual {
		diags.AddError("Invalid categorization",
			"baseline and individual objectives (confidentiality, integrity, availability) are mutually exclusive. Use one or the other.")
		return result, diags
	}

	// Rule: NSS requires explicit per-objective categorization, not baseline
	if nss && hasBaseline {
		diags.AddError("Invalid categorization for NSS",
			"National Security Systems require explicit per-objective categorization. "+
				"Set confidentiality, integrity, and availability instead of baseline.")
		return result, diags
	}

	// Rule: NSS requires all three objectives
	if nss && !(hasConf && hasInteg && hasAvail) {
		diags.AddError("Incomplete NSS categorization",
			"National Security Systems require all three objectives: confidentiality, integrity, and availability.")
		return result, diags
	}

	if hasBaseline {
		level := cat.Baseline.ValueString()
		if !validLevels[level] {
			diags.AddError("Invalid baseline level",
				fmt.Sprintf("baseline must be one of: low, moderate, high. Got: %q", level))
			return result, diags
		}
		// Expand baseline to all three objectives
		result.Confidentiality = level
		result.Integrity = level
		result.Availability = level
	} else if hasIndividual {
		// Validate each provided level
		if hasConf {
			if !validLevels[cat.Confidentiality.ValueString()] {
				diags.AddError("Invalid confidentiality level",
					fmt.Sprintf("confidentiality must be one of: low, moderate, high. Got: %q", cat.Confidentiality.ValueString()))
			}
			result.Confidentiality = cat.Confidentiality.ValueString()
		}
		if hasInteg {
			if !validLevels[cat.Integrity.ValueString()] {
				diags.AddError("Invalid integrity level",
					fmt.Sprintf("integrity must be one of: low, moderate, high. Got: %q", cat.Integrity.ValueString()))
			}
			result.Integrity = cat.Integrity.ValueString()
		}
		if hasAvail {
			if !validLevels[cat.Availability.ValueString()] {
				diags.AddError("Invalid availability level",
					fmt.Sprintf("availability must be one of: low, moderate, high. Got: %q", cat.Availability.ValueString()))
			}
			result.Availability = cat.Availability.ValueString()
		}
	}

	return result, diags
}
