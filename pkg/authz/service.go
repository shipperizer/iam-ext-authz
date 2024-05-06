// Copyright 2024 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package authz

import (
	"context"
	"net/http"
	"strings"

	kClient "github.com/ory/kratos-client-go"

	"github.com/shipperizer/iam-ext-authz/internal/logging"
	"github.com/shipperizer/iam-ext-authz/internal/monitoring"
	"github.com/shipperizer/iam-ext-authz/internal/tracing"
)

type Service struct {
	kratos KratosClientInterface
	hydra  HydraClientInterface

	tracer  tracing.TracingInterface
	monitor monitoring.MonitorInterface
	logger  logging.LoggerInterface
}

func (s *Service) CheckSession(ctx context.Context, cookies []*http.Cookie) (*kClient.Session, []*http.Cookie, error) {
	ctx, span := s.tracer.Start(ctx, "kratos.FrontendAPI.ToSession")
	defer span.End()

	strCookie := make([]string, 0)

	for _, c := range cookies {
		strCookie = append(strCookie, c.String())
	}

	session, resp, err := s.kratos.FrontendAPI().
		ToSession(ctx).
		Cookie(strings.Join(strCookie, "; ")).
		Execute()

	if err != nil {
		return nil, nil, err
	}
	return session, resp.Cookies(), nil
}

func (s *Service) CheckToken(ctx context.Context, IDToken string) (bool, string, error) {
	it, _, err := s.hydra.OAuth2API().IntrospectOAuth2Token(ctx).Token(IDToken).Execute()

	if err != nil {
		return false, "", err
	}

	return it.GetActive(), it.GetUsername(), nil
}

func (s *Service) CreateBrowserLoginFlow(
	ctx context.Context, aal, returnTo, loginChallenge string, refresh bool, cookies []*http.Cookie,
) (*kClient.LoginFlow, []*http.Cookie, error) {
	ctx, span := s.tracer.Start(ctx, "kratos.FrontendApi.CreateBrowserLoginFlow")
	defer span.End()

	strCookie := make([]string, 0)

	for _, c := range cookies {
		strCookie = append(strCookie, c.String())
	}

	flow, resp, err := s.kratos.FrontendAPI().
		CreateBrowserLoginFlow(context.Background()).
		Aal(aal).
		ReturnTo(returnTo).
		LoginChallenge(loginChallenge).
		Refresh(refresh).
		Cookie(strings.Join(strCookie, "; ")).
		Execute()

	if err != nil {
		s.logger.Debugf("full HTTP response: %v", resp)
		return nil, nil, err
	}

	return flow, resp.Cookies(), nil
}

func NewService(kratos KratosClientInterface, hydra HydraClientInterface, tracer tracing.TracingInterface, monitor monitoring.MonitorInterface, logger logging.LoggerInterface) *Service {
	s := new(Service)

	s.kratos = kratos
	s.hydra = hydra

	s.monitor = monitor
	s.tracer = tracer
	s.logger = logger

	return s
}
