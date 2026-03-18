// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testAccProtoV6ProviderFactories is used by acceptance tests.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"technitium": providerserver.NewProtocol6WithError(New("test")()),
}

func TestProviderSchema_NoError(t *testing.T) {
	p := New("test")()
	schemaResp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, schemaResp)

	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("provider schema returned errors: %v", schemaResp.Diagnostics)
	}

	// Verify key attributes exist
	attrs := schemaResp.Schema.Attributes
	for _, key := range []string{"server_url", "api_token", "skip_tls_verify"} {
		if _, ok := attrs[key]; !ok {
			t.Errorf("expected attribute %q in provider schema", key)
		}
	}

	// Verify stig_compliance block exists
	blocks := schemaResp.Schema.Blocks
	if _, ok := blocks["stig_compliance"]; !ok {
		t.Error("expected stig_compliance block in provider schema")
	}
}

func TestValidateCategorization_NSSWithBaseline(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringValue("moderate"),
		Confidentiality: types.StringNull(),
		Integrity:       types.StringNull(),
		Availability:    types.StringNull(),
	}
	_, diags := validateCategorization(cat, true)
	if !diags.HasError() {
		t.Error("expected error for NSS + baseline")
	}
}

func TestValidateCategorization_NSSMissingObjective(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringNull(),
		Confidentiality: types.StringValue("high"),
		Integrity:       types.StringValue("moderate"),
		Availability:    types.StringNull(),
	}
	_, diags := validateCategorization(cat, true)
	if !diags.HasError() {
		t.Error("expected error for NSS with missing availability")
	}
}

func TestValidateCategorization_NSSValid(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringNull(),
		Confidentiality: types.StringValue("moderate"),
		Integrity:       types.StringValue("high"),
		Availability:    types.StringValue("moderate"),
	}
	result, diags := validateCategorization(cat, true)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
	if result.Confidentiality != "moderate" {
		t.Errorf("expected confidentiality=moderate, got %s", result.Confidentiality)
	}
	if result.Integrity != "high" {
		t.Errorf("expected integrity=high, got %s", result.Integrity)
	}
	if result.Availability != "moderate" {
		t.Errorf("expected availability=moderate, got %s", result.Availability)
	}
}

func TestValidateCategorization_BaselineExpands(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringValue("high"),
		Confidentiality: types.StringNull(),
		Integrity:       types.StringNull(),
		Availability:    types.StringNull(),
	}
	result, diags := validateCategorization(cat, false)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
	for _, level := range []string{result.Confidentiality, result.Integrity, result.Availability} {
		if level != "high" {
			t.Errorf("expected all objectives=high, got %s", level)
		}
	}
}

func TestValidateCategorization_BaselineAndIndividualMutuallyExclusive(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringValue("moderate"),
		Confidentiality: types.StringValue("high"),
		Integrity:       types.StringNull(),
		Availability:    types.StringNull(),
	}
	_, diags := validateCategorization(cat, false)
	if !diags.HasError() {
		t.Error("expected error for baseline + individual objectives")
	}
}

func TestValidateCategorization_InvalidLevel(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringValue("critical"),
		Confidentiality: types.StringNull(),
		Integrity:       types.StringNull(),
		Availability:    types.StringNull(),
	}
	_, diags := validateCategorization(cat, false)
	if !diags.HasError() {
		t.Error("expected error for invalid baseline level 'critical'")
	}
}

func TestValidateCategorization_NonNSSIndividual(t *testing.T) {
	cat := &CategorizationModel{
		Baseline:        types.StringNull(),
		Confidentiality: types.StringValue("low"),
		Integrity:       types.StringValue("moderate"),
		Availability:    types.StringValue("high"),
	}
	result, diags := validateCategorization(cat, false)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
	if result.Confidentiality != "low" || result.Integrity != "moderate" || result.Availability != "high" {
		t.Error("individual objectives not preserved correctly")
	}
}
