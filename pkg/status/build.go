// Copyright 2024 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package status

import (
	"runtime/debug"

	"github.com/shipperizer/iam-ext-authz/internal/version"
)

type BuildInfo struct {
	Version    string `json:"version"`
	CommitHash string `json:"commit_hash"`
	Name       string `json:"name"`
}

func buildInfo() *BuildInfo {
	info, ok := debug.ReadBuildInfo()

	if !ok {
		return nil
	}

	buildInfo := new(BuildInfo)
	buildInfo.Name = info.Main.Path
	buildInfo.Version = version.Version
	buildInfo.CommitHash = gitRevision(info.Settings)

	return buildInfo
}

func gitRevision(settings []debug.BuildSetting) string {
	for _, setting := range settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}

	return "n/a"
}
