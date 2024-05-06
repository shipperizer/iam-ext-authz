// Copyright 2024 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package web

import (
	"github.com/shipperizer/iam-ext-authz/internal/logging"
	"github.com/shipperizer/iam-ext-authz/internal/monitoring"
	"github.com/shipperizer/iam-ext-authz/internal/tracing"
)

// O11yConfig is a wrapper config for all the observability objects
type O11yConfig struct {
	tracer  tracing.TracingInterface
	monitor monitoring.MonitorInterface
	logger  logging.LoggerInterface
}

// Tracer returns the tracing object
func (c *O11yConfig) Tracer() tracing.TracingInterface {
	return c.tracer
}

// Monitor returns a monitor object
func (c *O11yConfig) Monitor() monitoring.MonitorInterface {
	return c.monitor
}

// Logger returns a logger object
func (c *O11yConfig) Logger() logging.LoggerInterface {
	return c.logger
}

// NewO11yConfig create an observability config object with a monitor, logger and tracer
func NewO11yConfig(tracer tracing.TracingInterface, monitor monitoring.MonitorInterface, logger logging.LoggerInterface) *O11yConfig {
	c := new(O11yConfig)

	c.tracer = tracer
	c.monitor = monitor
	c.logger = logger

	return c
}
