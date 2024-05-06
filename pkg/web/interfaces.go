// Copyright 2024 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package web

import (
	"github.com/shipperizer/iam-ext-authz/internal/logging"
	"github.com/shipperizer/iam-ext-authz/internal/monitoring"
	"github.com/shipperizer/iam-ext-authz/internal/tracing"
)

type O11yConfigInterface interface {
	Tracer() tracing.TracingInterface
	Monitor() monitoring.MonitorInterface
	Logger() logging.LoggerInterface
}
