package login

import (
	"errors"
	"net/http"

	"golang.org/x/oauth2"
)

// Transport is an [http.RoundTripper] that makes Lieutenant flavored authenticated HTTP requests.
// It wraps a base [http.RoundTripper] and adding an Authorization header
// with a token from the supplied [TokenSource].
//
// It reads `id_token` from `oauth2.Token.Extra` and adds it as a Bearer token to the Authorization header.
// I'm not sure how spec compliant this is. 🤷
//
// Transport is a low-level mechanism. Most code will use the
// higher-level [Config.Client] method instead.
type Transport struct {
	// Source supplies the token to add to outgoing requests'
	// Authorization headers.
	Source oauth2.TokenSource

	// Base is the base RoundTripper used to make HTTP requests.
	// If nil, http.DefaultTransport is used.
	Base http.RoundTripper
}

// RoundTrip authorizes and authenticates the request with an
// access token from Transport's Source.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBodyClosed := false
	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				_ = req.Body.Close()
			}
		}()
	}

	if t.Source == nil {
		return nil, errors.New("oauth2: Transport's Source is nil")
	}
	token, err := t.Source.Token()
	if err != nil {
		return nil, err
	}

	idToken, hasIDToken := token.Extra("id_token").(string)
	if !hasIDToken || idToken == "" {
		return nil, errors.New("lieutenant flavoured openid: TokenSource returned a token with no id_token in Extra")
	}

	req2 := req.Clone(req.Context())
	token.SetAuthHeader(req2)
	req2.Header.Set("Authorization", "Bearer "+idToken)

	// req.Body is assumed to be closed by the base RoundTripper.
	reqBodyClosed = true
	return t.base().RoundTrip(req2)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}
