// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/darkhonor/terraform-provider-technitium/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var (
	version string = "dev"
	commit  string = "none"
)

func main() {
	var debug bool
	var showVersion bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.BoolVar(&showVersion, "version", false, "print version information and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("terraform-provider-technitium %s (commit: %s)\n", version, commit)
		return
	}

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/darkhonor/technitium",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
