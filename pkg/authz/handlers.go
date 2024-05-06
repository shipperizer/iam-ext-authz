// Copyright 2024 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package authz

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/shipperizer/iam-ext-authz/internal/logging"
)

const (
	checkHeader    = "x-ext-authz"
	allowedValue   = "allow"
	resultHeader   = "x-ext-authz-check-result"
	receivedHeader = "x-ext-authz-check-received"
	overrideHeader = "x-ext-authz-additional-header-override"
	resultAllowed  = "allowed"
	resultDenied   = "denied"
	kubeflowHeader = "kubeflow-userid"
)

var (
	denyBody = fmt.Sprintf("denied by ext_authz for not found header `%s: %s` in the request", checkHeader, allowedValue)
)

type API struct {
	logger logging.LoggerInterface

	service ServiceInterface
}

func (a *API) RegisterEndpoints(mux *chi.Mux) {
	mux.Get("/api/v0/check", a.check)
}

func (a *API) check(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		a.logger.Infof("[HTTP] read body failed: %v", err)
	}

	l := fmt.Sprintf("%s %s%s, headers: %v, body: [%s]\n", r.Method, r.Host, r.URL, r.Header, body)

	IDToken := ""
	authorization := r.Header.Get("Authorization")

	if authorization != "" {
		IDToken = strings.TrimSpace(strings.Replace(authorization, "Bearer", "", 1))
	}

	if IDToken != "" {
		active, username, err := a.service.CheckToken(r.Context(), IDToken)

		if err != nil {
			a.logger.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !active {
			a.logger.Infof("Token not active: %s", IDToken)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		a.logger.Infof("[HTTP][allowed]: %s", l)
		w.Header().Set(kubeflowHeader, username)
		w.WriteHeader(http.StatusOK)

		return
	}

	session, _, err := a.service.CheckSession(r.Context(), r.Cookies())

	if err != nil {
		a.logger.Error(err)

		q := r.URL.Query()
		loginChallenge := q.Get("login_challenge")

		refresh, err := strconv.ParseBool(q.Get("refresh"))

		refresh = refresh || !(err == nil)

		returnTo := fmt.Sprintf("%s?login_challenge=%s", r.URL.Path, loginChallenge)

		flow, cookies, err := a.service.CreateBrowserLoginFlow(context.Background(), q.Get("aal"), returnTo, loginChallenge, refresh, r.Cookies())
		if err != nil {
			http.Error(w, "Failed to create login flow", http.StatusInternalServerError)
			return
		}

		resp, err := flow.MarshalJSON()

		if err != nil {
			a.logger.Errorf("Error when marshalling Json: %v\n", err)
			http.Error(w, "Failed to marshall json", http.StatusInternalServerError)
			return
		}

		for _, c := range cookies {
			http.SetCookie(w, c)
		}

		w.WriteHeader(http.StatusOK)
		w.Write(resp)

		return
	}

	if session != nil && *session.Active {
		a.logger.Infof("[HTTP][allowed]: %s", l)
		w.Header().Set(kubeflowHeader, session.GetIdentity().Id)
		w.Header().Set(resultHeader, resultAllowed)
		w.WriteHeader(http.StatusOK)

		return
	}

	switch r.Header.Get(checkHeader) {
	case allowedValue:
		a.logger.Infof("[HTTP][allowed]: %s", l)
		w.Header().Set(resultHeader, resultAllowed)
		w.Header().Set(overrideHeader, r.Header.Get(overrideHeader))
		w.Header().Set(receivedHeader, l)
		w.WriteHeader(http.StatusOK)
	default:
		a.logger.Infof("[HTTP][denied]: %s", l)
		w.Header().Set(resultHeader, resultDenied)
		w.Header().Set(overrideHeader, r.Header.Get(overrideHeader))
		w.Header().Set(receivedHeader, l)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(denyBody))
	}
}

func NewAPI(service ServiceInterface, logger logging.LoggerInterface) *API {
	a := new(API)

	a.service = service
	a.logger = logger

	return a
}
