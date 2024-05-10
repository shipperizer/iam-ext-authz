// Copyright 2024 Canonical Ltd
// SPDX-License-Identifier: AGPL

package monitoring

import (
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/shipperizer/iam-ext-authz/internal/logging"
)

const (
	// IDPathRegex regexp used to swap the {id*} parameters in the path with simply id
	// supports alphabetic characters and underscores, no dashes
	IDPathRegex string = "{[a-zA-Z_]*}"
)

// Middleware is the monitoring middleware object implementing Prometheus monitoring
type Middleware struct {
	service string
	regex   *regexp.Regexp

	monitor MonitorInterface
	logger  logging.LoggerInterface
}

func (mdw *Middleware) ResponseTime() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
				startTime := time.Now()

				next.ServeHTTP(ww, r)

				tags := map[string]string{
					"route":  fmt.Sprintf("%s%s", r.Method, mdw.regex.ReplaceAll([]byte(r.URL.Path), []byte("id"))),
					"status": fmt.Sprint(ww.Status()),
				}

				m, err := mdw.monitor.GetResponseTimeMetric(tags)

				if err != nil {
					mdw.logger.Debugf("error fetching metric: %s; keep going....", err)

					return
				}

				m.Observe(time.Since(startTime).Seconds())
			},
		)
	}
}

// NewMiddleware returns a Middleware based on the type of monitor
func NewMiddleware(monitor MonitorInterface, logger logging.LoggerInterface) *Middleware {
	mdw := new(Middleware)

	mdw.monitor = monitor

	mdw.service = monitor.GetService()
	mdw.logger = logger
	mdw.regex = regexp.MustCompile(IDPathRegex)

	return mdw
}
