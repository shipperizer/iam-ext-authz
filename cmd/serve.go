// Copyright 2024 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0

package cmd

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	corev2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev2 "github.com/envoyproxy/go-control-plane/envoy/type"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/kelseyhightower/envconfig"
	"github.com/spf13/cobra"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"

	"github.com/shipperizer/iam-ext-authz/internal/config"
	ih "github.com/shipperizer/iam-ext-authz/internal/hydra"
	ik "github.com/shipperizer/iam-ext-authz/internal/kratos"
	"github.com/shipperizer/iam-ext-authz/internal/logging"
	"github.com/shipperizer/iam-ext-authz/internal/monitoring/prometheus"
	"github.com/shipperizer/iam-ext-authz/internal/tracing"
	"github.com/shipperizer/iam-ext-authz/pkg/web"
)

type (
	extAuthzServerV2 struct{ Logger logging.LoggerInterface }
	extAuthzServerV3 struct{ Logger logging.LoggerInterface }
)

const (
	checkHeader       = "x-ext-authz"
	allowedValue      = "allow"
	resultHeader      = "x-ext-authz-check-result"
	receivedHeader    = "x-ext-authz-check-received"
	overrideHeader    = "x-ext-authz-additional-header-override"
	overrideGRPCValue = "grpc-additional-header-override-value"
	resultAllowed     = "allowed"
	resultDenied      = "denied"
)

var (
	serviceAccount = flag.String("allow_service_account", "a",
		"allowed service account, matched against the service account in the source principal from the client certificate")
	denyBody = fmt.Sprintf("denied by ext_authz for not found header `%s: %s` in the request", checkHeader, allowedValue)
)

func (s *extAuthzServerV2) logRequest(allow string, request *authv2.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	s.Logger.Debugf("[gRPCv2][%s]: %s%s, attributes: %v\n", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
}

func (s *extAuthzServerV2) allow(request *authv2.CheckRequest) *authv2.CheckResponse {
	s.logRequest("allowed", request)
	return &authv2.CheckResponse{
		HttpResponse: &authv2.CheckResponse_OkResponse{
			OkResponse: &authv2.OkHttpResponse{
				Headers: []*corev2.HeaderValueOption{
					{
						Header: &corev2.HeaderValue{
							Key:   resultHeader,
							Value: resultAllowed,
						},
					},
					{
						Header: &corev2.HeaderValue{
							Key:   receivedHeader,
							Value: request.GetAttributes().String(),
						},
					},
					{
						Header: &corev2.HeaderValue{
							Key:   overrideHeader,
							Value: overrideGRPCValue,
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.OK)},
	}
}

func (s *extAuthzServerV2) deny(request *authv2.CheckRequest) *authv2.CheckResponse {
	s.logRequest("denied", request)
	return &authv2.CheckResponse{
		HttpResponse: &authv2.CheckResponse_DeniedResponse{
			DeniedResponse: &authv2.DeniedHttpResponse{
				Status: &typev2.HttpStatus{Code: typev2.StatusCode_Forbidden},
				Body:   denyBody,
				Headers: []*corev2.HeaderValueOption{
					{
						Header: &corev2.HeaderValue{
							Key:   resultHeader,
							Value: resultDenied,
						},
					},
					{
						Header: &corev2.HeaderValue{
							Key:   receivedHeader,
							Value: request.GetAttributes().String(),
						},
					},
					{
						Header: &corev2.HeaderValue{
							Key:   overrideHeader,
							Value: overrideGRPCValue,
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
	}
}

// Check implements gRPC v2 check request.
func (s *extAuthzServerV2) Check(_ context.Context, request *authv2.CheckRequest) (*authv2.CheckResponse, error) {
	attrs := request.GetAttributes()

	// Determine whether to allow or deny the request.
	allow := false
	checkHeaderValue, contains := attrs.GetRequest().GetHttp().GetHeaders()[checkHeader]
	if contains {
		allow = checkHeaderValue == allowedValue
	} else {
		allow = attrs.Source != nil && strings.HasSuffix(attrs.Source.Principal, "/sa/"+*serviceAccount)
	}

	if allow {
		return s.allow(request), nil
	}

	return s.deny(request), nil
}

func (s *extAuthzServerV3) logRequest(allow string, request *authv3.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	s.Logger.Debugf("[gRPCv3][%s]: %s%s, attributes: %v\n", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
}

func (s *extAuthzServerV3) allow(request *authv3.CheckRequest) *authv3.CheckResponse {
	s.logRequest("allowed", request)
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   resultHeader,
							Value: resultAllowed,
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   receivedHeader,
							Value: request.GetAttributes().String(),
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   overrideHeader,
							Value: overrideGRPCValue,
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.OK)},
	}
}

func (s *extAuthzServerV3) deny(request *authv3.CheckRequest) *authv3.CheckResponse {
	s.logRequest("denied", request)
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   denyBody,
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   resultHeader,
							Value: resultDenied,
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   receivedHeader,
							Value: request.GetAttributes().String(),
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   overrideHeader,
							Value: overrideGRPCValue,
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
	}
}

// Check implements gRPC v3 check request.
func (s *extAuthzServerV3) Check(_ context.Context, request *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	attrs := request.GetAttributes()

	// Determine whether to allow or deny the request.
	allow := false
	checkHeaderValue, contains := attrs.GetRequest().GetHttp().GetHeaders()[checkHeader]
	if contains {
		allow = checkHeaderValue == allowedValue
	} else {
		allow = attrs.Source != nil && strings.HasSuffix(attrs.Source.Principal, "/sa/"+*serviceAccount)
	}

	if allow {
		return s.allow(request), nil
	}

	return s.deny(request), nil
}

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve starts the web server",
	Long:  `Launch the web application, list of environment variables is available in the README.`,
	Run: func(cmd *cobra.Command, args []string) {
		serve()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func serve() {

	specs := new(config.EnvSpec)

	if err := envconfig.Process("", specs); err != nil {
		panic(fmt.Errorf("issues with environment sourcing: %s", err))
	}

	logger := logging.NewLogger(specs.LogLevel, specs.LogFile)
	monitor := prometheus.NewMonitor("identity-admin-ui", logger)
	tracer := tracing.NewTracer(tracing.NewConfig(specs.TracingEnabled, specs.OtelGRPCEndpoint, specs.OtelHTTPEndpoint, logger))

	ollyConfig := web.NewO11yConfig(tracer, monitor, logger)

	kClient := ik.NewClient(specs.KratosPublicURL, specs.Debug)
	hClient := ih.NewClient(specs.HydraAdminURL, specs.Debug)

	router := web.NewRouter(kClient, hClient, ollyConfig)

	logger.Infof("Starting server on port %v", specs.Port)

	srv := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%v", specs.Port+1),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			logger.Fatal(err)
		}
	}()

	// hack a grpc server together quickly
	grpcSrv := grpc.NewServer()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%v", specs.Port))

	if err != nil {
		logger.Fatalf("Failed to start gRPC server: %v", err)
	}

	authv2.RegisterAuthorizationServer(grpcSrv, &extAuthzServerV2{Logger: logger})
	authv3.RegisterAuthorizationServer(grpcSrv, &extAuthzServerV3{Logger: logger})
	reflection.Register(grpcSrv)

	go func() {
		if err := grpcSrv.Serve(listener); err != nil {
			logger.Fatal(err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Block until we receive our signal.
	<-c

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	srv.Shutdown(ctx)

	logger.Desugar().Sync()

	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	logger.Info("Shutting down")
	os.Exit(0)

}
