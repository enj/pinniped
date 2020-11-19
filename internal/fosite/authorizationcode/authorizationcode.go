// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package authorizationcode

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"k8s.io/apimachinery/pkg/api/errors"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crud"
)

const (
	ErrInvalidAuthorizeRequestType    = constable.Error("authorization request must be of type fosite.AuthorizeRequest")
	ErrInvalidAuthorizeRequestData    = constable.Error("authorization request data must not be nil")
	ErrInvalidAuthorizeRequestVersion = constable.Error("authorization request data has wrong version")

	authorizeCodeStorageVersion = "1"
)

var _ oauth2.AuthorizeCodeStorage = &authorizeCodeStorage{}

type authorizeCodeStorage struct {
	storage crud.Storage
}

type authorizeCodeSession struct {
	Active  bool                     `json:"active"`
	Request *fosite.AuthorizeRequest `json:"request"`
	Version string                   `json:"version"`
}

func New(secrets corev1client.SecretInterface) oauth2.AuthorizeCodeStorage {
	return &authorizeCodeStorage{storage: crud.New("authorization-codes", secrets)}
}

func (a *authorizeCodeStorage) CreateAuthorizeCodeSession(ctx context.Context, signature string, requester fosite.Requester) error {
	// this conversion assumes that we do not wrap the default type in any way
	// i.e. we use the default fosite.OAuth2Provider.NewAuthorizeRequest implementation
	// note that because this type is serialized and stored in Kube, we cannot easily change the implementation later
	// TODO hydra uses the fosite.Request struct and ignores the extra fields in fosite.AuthorizeRequest
	request, err := validateAndExtractAuthorizeRequest(requester)
	if err != nil {
		return err
	}

	// TODO hydra stores specific fields from the requester
	//  request ID
	//  requestedAt
	//  OAuth client ID
	//  requested scopes, granted scopes
	//  requested audience, granted audience
	//  url encoded request form
	//  session as JSON bytes with (optional) encryption
	//  session subject
	//  consent challenge from session which is the identifier ("authorization challenge")
	//      of the consent authorization request. It is used to identify the session.
	//  signature for lookup in the DB

	_, err = a.storage.Create(ctx, signature, &authorizeCodeSession{Active: true, Request: request, Version: authorizeCodeStorageVersion})
	return err
}

func (a *authorizeCodeStorage) GetAuthorizeCodeSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	// TODO hydra uses the incoming fosite.Session to provide the type needed to json.Unmarshal their session bytes

	session, _, err := a.getSession(ctx, signature)
	if err != nil {
		return nil, err
	}

	// TODO hydra gets the client from its DB as a concrete type via client ID,
	//  the hydra memory client just validates that the client ID exists

	// TODO hydra uses the sha512.Sum384 hash of signature when using JWT as access token to reduce length

	return session.Request, nil
}

func (a *authorizeCodeStorage) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	// TODO write garbage collector for these codes

	session, rv, err := a.getSession(ctx, signature)
	if err != nil {
		return err
	}

	session.Active = false
	if _, err := a.storage.Update(ctx, signature, rv, session); err != nil {
		if errors.IsConflict(err) {
			return &errSerializationFailureWithCause{cause: err}
		}
		return err
	}

	return nil
}

func (a *authorizeCodeStorage) getSession(ctx context.Context, signature string) (*authorizeCodeSession, string, error) {
	session := newValidEmptyAuthorizeCodeSession()
	rv, err := a.storage.Get(ctx, signature, session)

	if errors.IsNotFound(err) {
		return nil, "", fosite.ErrNotFound.WithCause(err).WithDebug(err.Error())
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to get authorization code session for %s: %w", signature, err)
	}

	if version := session.Version; version != authorizeCodeStorageVersion {
		return nil, "", fmt.Errorf("%w: authorization code session for %s has version %s instead of %s",
			ErrInvalidAuthorizeRequestVersion, signature, version, authorizeCodeStorageVersion)
	}

	if session.Request == nil {
		return nil, "", fmt.Errorf("malformed authorization code session for %s: %w", signature, ErrInvalidAuthorizeRequestData)
	}

	if !session.Active {
		return nil, "", fmt.Errorf("authorization code session for %s has already been used: %w", signature, fosite.ErrInvalidatedAuthorizeCode)
	}

	return session, rv, nil
}

func newValidEmptyAuthorizeCodeSession() *authorizeCodeSession {
	return &authorizeCodeSession{
		Request: &fosite.AuthorizeRequest{
			Request: fosite.Request{
				Client:  &fosite.DefaultOpenIDConnectClient{},
				Session: &openid.DefaultSession{},
			},
		},
	}
}

func validateAndExtractAuthorizeRequest(requester fosite.Requester) (*fosite.AuthorizeRequest, error) {
	request, ok1 := requester.(*fosite.AuthorizeRequest)
	if !ok1 {
		return nil, ErrInvalidAuthorizeRequestType
	}
	_, ok2 := request.Client.(*fosite.DefaultOpenIDConnectClient)
	_, ok3 := request.Session.(*openid.DefaultSession)

	valid := ok2 && ok3
	if !valid {
		return nil, ErrInvalidAuthorizeRequestType
	}

	return request, nil
}

var _ interface {
	Is(error) bool
	Unwrap() error
	error
} = &errSerializationFailureWithCause{}

type errSerializationFailureWithCause struct {
	cause error
}

func (e *errSerializationFailureWithCause) Is(err error) bool {
	return stderrors.Is(fosite.ErrSerializationFailure, err)
}

func (e *errSerializationFailureWithCause) Unwrap() error {
	return e.cause
}

func (e *errSerializationFailureWithCause) Error() string {
	return fmt.Sprintf("%s: %s", fosite.ErrSerializationFailure, e.cause)
}
