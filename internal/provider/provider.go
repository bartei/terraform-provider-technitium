// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/bartei/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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
	ServerURL     types.String `tfsdk:"server_url"`
	APIToken      types.String `tfsdk:"api_token"`
	SkipTLSVerify types.Bool   `tfsdk:"skip_tls_verify"`
	CACertFile    types.String `tfsdk:"ca_cert_file"`
	CACertDir     types.String `tfsdk:"ca_cert_dir"`
	TLSServerName types.String `tfsdk:"tls_server_name"`
	TLSMinVersion types.String `tfsdk:"tls_min_version"`
}

// TechnitiumProviderData is passed to resources via req.ProviderData.
type TechnitiumProviderData struct {
	Client *client.Client
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
		Description: "Terraform provider for managing Technitium DNS Server.",
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
				Description: "Skip TLS certificate verification.",
				Optional:    true,
			},
			"ca_cert_file": schema.StringAttribute{
				Description: "Path to a PEM-encoded CA certificate file to validate the Technitium server's TLS certificate. " +
					"May be set via the TECHNITIUM_CACERT environment variable.",
				Optional: true,
			},
			"ca_cert_dir": schema.StringAttribute{
				Description: "Path to a directory of PEM-encoded CA certificate files to validate the Technitium server's TLS certificate. " +
					"Files that fail to parse are skipped. May be set via the TECHNITIUM_CAPATH environment variable.",
				Optional: true,
			},
			"tls_server_name": schema.StringAttribute{
				Description: "Name to use as the SNI host when connecting to the Technitium server via TLS. " +
					"May be set via the TECHNITIUM_TLS_SERVER_NAME environment variable.",
				Optional: true,
			},
			"tls_min_version": schema.StringAttribute{
				Description: "Minimum TLS version to accept when connecting to the Technitium server. " +
					"Valid values: \"1.2\", \"1.3\". Defaults to \"1.3\". " +
					"May be set via the TECHNITIUM_TLS_MIN_VERSION environment variable.",
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf("1.2", "1.3"),
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

	// Resolve TLS configuration (HCL > env var > default)
	var skipTLSPtr *bool
	if !config.SkipTLSVerify.IsNull() {
		v := config.SkipTLSVerify.ValueBool()
		skipTLSPtr = &v
	}
	skipTLSVerify, err := resolveTLSBool(skipTLSPtr, "TECHNITIUM_SKIP_TLS_VERIFY", false)
	if err != nil {
		resp.Diagnostics.AddError("Invalid TLS configuration", err.Error())
		return
	}

	caCertFile := resolveTLSString(config.CACertFile.ValueString(), "TECHNITIUM_CACERT")
	caCertDir := resolveTLSString(config.CACertDir.ValueString(), "TECHNITIUM_CAPATH")
	tlsServerName := resolveTLSString(config.TLSServerName.ValueString(), "TECHNITIUM_TLS_SERVER_NAME")
	tlsMinVersion, err := resolveTLSMinVersion(config.TLSMinVersion.ValueString(), "TECHNITIUM_TLS_MIN_VERSION", "1.3")
	if err != nil {
		resp.Diagnostics.AddError("Invalid TLS configuration", err.Error())
		return
	}

	// Create API client
	apiClient, err := client.NewClient(client.ClientConfig{
		BaseURL:       serverURL,
		Token:         apiToken,
		SkipTLSVerify: skipTLSVerify,
		CACertFile:    caCertFile,
		CACertDir:     caCertDir,
		TLSServerName: tlsServerName,
		TLSMinVersion: tlsMinVersion,
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to create API client", err.Error())
		return
	}

	// Verify connectivity with TLS-aware error diagnostics
	if err := apiClient.Ping(ctx); err != nil {
		isHTTPS := strings.HasPrefix(serverURL, "https://")
		if isHTTPS {
			tlsErr := client.ClassifyTLSError(err)
			if diagnostic := buildTLSDiagnostic(tlsErr, serverURL); diagnostic != "" {
				resp.Diagnostics.AddError("TLS connection failed", diagnostic)
				return
			}
		}
		resp.Diagnostics.AddError("Unable to connect to Technitium server",
			fmt.Sprintf("Ping to %s failed: %s", serverURL, err.Error()))
		return
	}

	providerData := &TechnitiumProviderData{Client: apiClient}

	resp.DataSourceData = providerData
	resp.ResourceData = providerData
}

func (p *TechnitiumProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewZoneResource,
		NewRecordResource,
		NewServerSettingsResource,
		NewTSIGKeyResource,
		NewBlockedZoneResource,
		NewBlockedZonesResource,
		NewAllowedZoneResource,
		NewAllowedZonesResource,
		NewCatalogMembershipResource,
	}
}

func (p *TechnitiumProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewZoneDataSource,
		NewRecordDataSource,
		NewServerSettingsDataSource,
		NewTSIGKeyDataSource,
		NewBlockedZoneDataSource,
		NewBlockedZonesDataSource,
		NewAllowedZoneDataSource,
		NewAllowedZonesDataSource,
	}
}

// resolveTLSString resolves a TLS string config value with HCL > env var > empty precedence.
func resolveTLSString(hclValue, envVar string) string {
	if hclValue != "" {
		return hclValue
	}
	return os.Getenv(envVar)
}

// resolveTLSBool resolves a TLS bool config value with HCL > env var > default precedence.
func resolveTLSBool(hclValue *bool, envVar string, defaultVal bool) (bool, error) {
	if hclValue != nil {
		return *hclValue, nil
	}
	envStr := os.Getenv(envVar)
	if envStr != "" {
		val, err := strconv.ParseBool(envStr)
		if err != nil {
			return false, fmt.Errorf("invalid value for %s: %q (expected true/false)", envVar, envStr)
		}
		return val, nil
	}
	return defaultVal, nil
}

// resolveTLSMinVersion resolves the TLS minimum version with HCL > env var > default precedence.
func resolveTLSMinVersion(hclValue, envVar, defaultVal string) (string, error) {
	result := hclValue
	if result == "" {
		result = os.Getenv(envVar)
	}
	if result == "" {
		return defaultVal, nil
	}
	if result != "1.2" && result != "1.3" {
		return "", fmt.Errorf("invalid value for %s: %q (must be \"1.2\" or \"1.3\")", envVar, result)
	}
	return result, nil
}

// buildTLSDiagnostic produces a context-aware error message for TLS handshake
// failures. Returns an empty string when the error is not TLS-related (caller
// falls through to the generic connectivity error).
func buildTLSDiagnostic(tlsErr client.TLSError, serverURL string) string {
	switch tlsErr.Kind {
	case client.TLSErrVersionMismatch:
		return fmt.Sprintf("Connection to %s failed: TLS 1.3 not supported by the server.", serverURL) +
			" To resolve, either:\n" +
			"  - Upgrade the server's TLS configuration to support TLS 1.3\n" +
			"  - Set tls_min_version = \"1.2\" in the provider configuration\n" +
			"  - Set skip_tls_verify = true to bypass certificate verification entirely"
	case client.TLSErrUnknownAuthority:
		return fmt.Sprintf("Connection to %s failed: server certificate signed by unknown authority.", serverURL) +
			" To resolve, either:\n" +
			"  - Configure ca_cert_file or ca_cert_dir with the CA certificate that signed the server's certificate\n" +
			"  - Set skip_tls_verify = true to bypass certificate verification entirely"
	case client.TLSErrCertificateInvalid, client.TLSErrHostnameMismatch:
		return fmt.Sprintf("Connection to %s failed: server certificate verification failed.", serverURL) +
			" To resolve, either:\n" +
			"  - Verify the correct CA chain is configured in ca_cert_file or ca_cert_dir\n" +
			"  - Set skip_tls_verify = true to bypass certificate verification entirely"
	case client.TLSErrNotTLS:
		return ""
	}
	return ""
}
