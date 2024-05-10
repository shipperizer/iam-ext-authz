// Copyright 2024 Canonical Ltd
// SPDX-License-Identifier: AGPL

package monitoring

import (
	"github.com/shipperizer/iam-ext-authz/internal/logging"
)

type NoopMonitor struct {
	service string

	logger logging.LoggerInterface
}

type NoopMetricInterface struct{}

func (m *NoopMetricInterface) Observe(float64) {}

func NewNoopMonitor(service string, logger logging.LoggerInterface) *NoopMonitor {
	m := new(NoopMonitor)
	m.service = service
	m.logger = logger
	return m
}

func (m *NoopMonitor) GetService() string {
	return m.service
}
func (m *NoopMonitor) SetResponseTimeMetric(map[string]string, float64) error {
	return nil
}
func (m *NoopMonitor) SetDependencyAvailability(map[string]string, float64) error {
	return nil
}

func (m *NoopMonitor) GetResponseTimeMetric(tags map[string]string) (MetricInterface, error) {
	return new(NoopMetricInterface), nil
}
