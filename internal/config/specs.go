// Copyright 2024 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0

package config

// EnvSpec is the basic environment configuration setup needed for the app to start
type EnvSpec struct {
	OtelGRPCEndpoint string `envconfig:"otel_grpc_endpoint"`
	OtelHTTPEndpoint string `envconfig:"otel_http_endpoint"`
	TracingEnabled   bool   `envconfig:"tracing_enabled" default:"true"`

	LogLevel string `envconfig:"log_level" default:"error"`
	LogFile  string `envconfig:"log_file" default:"log.txt"`

	Port int `envconfig:"port" default:"8000"`

	Debug bool `envconfig:"debug" default:"false"`

	KratosPublicURL string `envconfig:"kratos_public_url" required:"false"`
	HydraAdminURL   string `envconfig:"hydra_admin_url" required:"false"`
}
