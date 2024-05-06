// Copyright 2024 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0

package authz

import (
	"context"
	"net/http"

	hClient "github.com/ory/hydra-client-go/v2"
	kClient "github.com/ory/kratos-client-go"
)

type KratosClientInterface interface {
	FrontendAPI() kClient.FrontendAPI
}

type HydraClientInterface interface {
	OAuth2API() hClient.OAuth2API
}

type AuthorizerInterface interface {
	ListObjects(context.Context, string, string, string) ([]string, error)
}

type ServiceInterface interface {
	CheckSession(context.Context, []*http.Cookie) (*kClient.Session, []*http.Cookie, error)
	CheckToken(context.Context, string) (bool, string, error)
	CreateBrowserLoginFlow(context.Context, string, string, string, bool, []*http.Cookie) (*kClient.LoginFlow, []*http.Cookie, error)
}
