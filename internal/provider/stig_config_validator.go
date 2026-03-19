// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/darkhonor/terraform-provider-technitium/internal/provider/validators"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// stigConfigValidator implements resource.ConfigValidator for STIG compliance checks.
type stigConfigValidator struct {
	engine   *validators.Engine
	resource validators.TargetResource
}

func newSTIGConfigValidator(engine *validators.Engine, resource validators.TargetResource) stigConfigValidator {
	return stigConfigValidator{engine: engine, resource: resource}
}

func (v stigConfigValidator) Description(ctx context.Context) string {
	return "Validates resource configuration against DNS STIG security requirements"
}

func (v stigConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v stigConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	v.engine.ValidateConfig(ctx, v.resource, &validators.TFConfigAdapter{Config: req.Config}, &resp.Diagnostics)
}
