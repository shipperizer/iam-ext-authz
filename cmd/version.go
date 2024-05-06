// Copyright 2024 Canonical Ltd
// SPDX-License-Identifier: AGPL

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/shipperizer/iam-ext-authz/internal/version"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Get the application's version.",
	Long:  `Get the application's version.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("App Version: %s\n", version.Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
