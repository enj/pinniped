// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidc contains common OIDC functionality needed by Pinniped.
package oidc

import (
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

const (
	WellKnownEndpointPath     = "/.well-known/openid-configuration"
	AuthorizationEndpointPath = "/oauth2/authorize"
	TokenEndpointPath         = "/oauth2/token" //nolint:gosec // ignore lint warning that this is a credential
	JWKSEndpointPath          = "/jwks.json"
)

func PinnipedCLIOIDCClient() *fosite.DefaultOpenIDConnectClient {
	return &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            "pinniped-cli",
			Public:        true,
			RedirectURIs:  []string{"http://127.0.0.1/callback"},
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code"},
			Scopes:        []string{"openid", "pinniped:all"}, // TODO require pinniped:all
			Audience:      []string{},                         // TODO
		},
	}
}

func FositeOauth2Helper(issuerURL string, oauthStore fosite.Storage, hmacSecretOfLengthAtLeast32 []byte) fosite.OAuth2Provider {
	oauthConfig := &compose.Config{
		AuthorizeCodeLifespan: 3 * time.Minute,

		IDTokenLifespan:     10 * time.Minute,
		AccessTokenLifespan: 10 * time.Minute,

		RefreshTokenLifespan: 16 * time.Hour,

		IDTokenIssuer: issuerURL,
		TokenURL:      "TODO", // TODO

		ScopeStrategy:            fosite.ExactScopeStrategy, // be careful
		AudienceMatchingStrategy: nil,                       // I think the default is fine
		EnforcePKCE:              true,                      // follow current set of best practices
		AllowedPromptValues:      []string{"none"},          // eeh?

		RefreshTokenScopes:  nil,
		MinParameterEntropy: 32, // ?
	}

	return compose.Compose(
		oauthConfig,
		oauthStore,
		&compose.CommonStrategy{
			// Note that Fosite requires the HMAC secret to be at least 32 bytes.
			CoreStrategy: compose.NewOAuth2HMACStrategy(oauthConfig, hmacSecretOfLengthAtLeast32, nil),
		},
		nil, // hasher, defaults to using BCrypt when nil. Used for hashing client secrets.
		compose.OAuth2AuthorizeExplicitFactory,
		// compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		// compose.OpenIDConnectRefreshFactory,
		compose.OAuth2PKCEFactory,
	)
}
