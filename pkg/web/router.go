// Copyright 2024 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0

package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	ih "github.com/shipperizer/iam-ext-authz/internal/hydra"
	ik "github.com/shipperizer/iam-ext-authz/internal/kratos"
	"github.com/shipperizer/iam-ext-authz/internal/logging"
	"github.com/shipperizer/iam-ext-authz/internal/monitoring"
	"github.com/shipperizer/iam-ext-authz/internal/tracing"
	"github.com/shipperizer/iam-ext-authz/pkg/authz"
	"github.com/shipperizer/iam-ext-authz/pkg/metrics"
	"github.com/shipperizer/iam-ext-authz/pkg/status"
)

func NewRouter(kratos *ik.Client, hydra *ih.Client, cfg O11yConfigInterface) http.Handler {
	router := chi.NewMux()

	logger := cfg.Logger()
	monitor := cfg.Monitor()
	tracer := cfg.Tracer()

	middlewares := make(chi.Middlewares, 0)
	middlewares = append(
		middlewares,
		middleware.RequestID,
		monitoring.NewMiddleware(monitor, logger).ResponseTime(),
		middlewareCORS([]string{"*"}),
	)

	// TODO @shipperizer add a proper configuration to enable http logger middleware as it's expensive
	if true {
		middlewares = append(
			middlewares,
			middleware.RequestLogger(logging.NewLogFormatter(logger)), // LogFormatter will only work if logger is set to DEBUG level
		)
	}

	router.Use(middlewares...)

	statusAPI := status.NewAPI(tracer, monitor, logger)
	metricsAPI := metrics.NewAPI(logger)
	extAuthzAPI := authz.NewAPI(authz.NewService(kratos, hydra, tracer, monitor, logger), logger)

	// register endpoints as last step
	statusAPI.RegisterEndpoints(router)
	metricsAPI.RegisterEndpoints(router)
	extAuthzAPI.RegisterEndpoints(router)

	return tracing.NewMiddleware(monitor, logger).OpenTelemetry(router)
}
