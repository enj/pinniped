// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"

	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/plog"
)

// FactoryFunc is a function which can create an impersonator server.
// It returns a function which will start the impersonator server.
// That start function takes a stopCh which can be used to stop the server.
// Once a server has been stopped, don't start it again using the start function.
// Instead, call the factory function again to get a new start function.
type FactoryFunc func(
	port int,
	dynamicCertProvider dynamiccertificates.CertKeyContentProvider,
	impersonationProxySignerCA dynamiccertificates.CAContentProvider,
) (func(stopCh <-chan struct{}) error, error)

func New(
	port int,
	dynamicCertProvider dynamiccertificates.CertKeyContentProvider,
	impersonationProxySignerCA dynamiccertificates.CAContentProvider,
) (func(stopCh <-chan struct{}) error, error) {
	// bare minimum server side scheme
	scheme := runtime.NewScheme()
	metav1.AddToGroupVersion(scheme, metav1.Unversioned)
	codecs := serializer.NewCodecFactory(scheme)

	// this is unused for now but it is a safe value that we could use in the future
	defaultEtcdPathPrefix := "/pinniped-impersonation-proxy-registry"

	recommendedOptions := genericoptions.NewRecommendedOptions(
		defaultEtcdPathPrefix,
		codecs.LegacyCodec(),
	)
	recommendedOptions.Etcd = nil // turn off etcd storage because we don't need it yet
	recommendedOptions.SecureServing.ServerCert.GeneratedCert = dynamicCertProvider
	recommendedOptions.SecureServing.BindPort = port

	// wire up the impersonation proxy signer CA as a valid authenticator
	// TODO fix comments
	kubeClient, err := kubeclient.New()
	if err != nil {
		return nil, err
	}

	kubeClientCA, err := dynamiccertificates.NewDynamicCAFromConfigMapController("client-ca", metav1.NamespaceSystem, "extension-apiserver-authentication", "client-ca-file", kubeClient.Kubernetes)
	if err != nil {
		return nil, err
	}
	recommendedOptions.Authentication.ClientCert.ClientCA = "---irrelevant-but-needs-to-be-non-empty---"
	recommendedOptions.Authentication.ClientCert.CAContentProvider = dynamiccertificates.NewUnionCAContentProvider(impersonationProxySignerCA, kubeClientCA)

	serverConfig := genericapiserver.NewRecommendedConfig(codecs)
	if err := recommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	impersonationProxy, err := newImpersonationReverseProxy(rest.CopyConfig(kubeClient.JSONConfig))
	if err != nil {
		return nil, err
	}

	defaultBuildHandlerChainFunc := serverConfig.BuildHandlerChainFunc
	serverConfig.BuildHandlerChainFunc = func(_ http.Handler, c *genericapiserver.Config) http.Handler {
		// we ignore the passed in handler because we never have any REST APIs to delegate to
		handler := defaultBuildHandlerChainFunc(impersonationProxy, c)
		handler = securityheader.Wrap(handler)
		return handler
	}

	// TODO integration test this authorizer logic with system:masters + double impersonation
	// empty string is disallowed because request info has had bugs in the past where it would leave it empty
	disallowedVerbs := sets.NewString("", "impersonate")
	noImpersonationAuthorizer := authorizer.AuthorizerFunc(func(a authorizer.Attributes) (authorizer.Decision, string, error) {
		// supporting impersonation is not hard, it would just require a bunch of testing
		// and configuring the audit layer (to preserve the caller) which we can do later
		// we would also want to delete the incoming impersonation headers
		if disallowedVerbs.Has(a.GetVerb()) {
			return authorizer.DecisionDeny, "impersonation is not allowed or invalid verb", nil
		}

		return authorizer.DecisionAllow, "defering authorization to kube API server", nil
	})
	// TODO write a big comment explaining wth this is doing
	serverConfig.Authorization.Authorizer = noImpersonationAuthorizer
	completedConfig := serverConfig.Complete()
	completedConfig.Authorization.Authorizer = noImpersonationAuthorizer

	impersonationProxyServer, err := completedConfig.New("impersonation-proxy", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	runFunc := impersonationProxyServer.PrepareRun().Run

	return runFunc, nil
}

func newImpersonationReverseProxy(restConfig *rest.Config) (http.Handler, error) {
	serverURL, err := url.Parse(restConfig.Host)
	if err != nil {
		return nil, fmt.Errorf("could not parse host URL from in-cluster config: %w", err)
	}

	kubeTransportConfig, err := restConfig.TransportConfig()
	if err != nil {
		return nil, fmt.Errorf("could not get in-cluster transport config: %w", err)
	}
	kubeTransportConfig.TLS.NextProtos = []string{"http/1.1"} // TODO huh?

	kubeRoundTripper, err := transport.New(kubeTransportConfig)
	if err != nil {
		return nil, fmt.Errorf("could not get in-cluster transport: %w", err)
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(serverURL)
	reverseProxy.Transport = kubeRoundTripper
	reverseProxy.FlushInterval = 200 * time.Millisecond // the "watch" verb will not work without this line

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO integration test using a bearer token
		if len(r.Header.Values("Authorization")) != 0 {
			plog.Warning("aggregated API server logic did not delete authorization header but it is always supposed to do so",
				"url", r.URL.String(),
				"method", r.Method,
			)
			http.Error(w, "invalid authorization header", http.StatusInternalServerError)
			return
		}

		if err := ensureNoImpersonationHeaders(r); err != nil {
			plog.Error("noImpersonationAuthorizer logic did not prevent nested impersonation but it is always supposed to do so",
				err,
				"url", r.URL.String(),
				"method", r.Method,
			)
			http.Error(w, "invalid impersonation", http.StatusInternalServerError)
			return
		}

		userInfo, ok := request.UserFrom(r.Context())
		if !ok {
			plog.Warning("aggregated API server logic did not set user info but it is always supposed to do so",
				"url", r.URL.String(),
				"method", r.Method,
			)
			http.Error(w, "invalid user", http.StatusInternalServerError)
			return
		}

		if len(userInfo.GetUID()) > 0 {
			plog.Warning("rejecting request with UID since we cannot impersonate UIDs",
				"url", r.URL.String(),
				"method", r.Method,
			)
			http.Error(w, "unexpected uid", http.StatusUnprocessableEntity)
			return
		}

		// Never mutate request (see http.Handler docs).
		newR := r.Clone(r.Context())
		newR.Header = getProxyHeaders(userInfo, r.Header)

		plog.Trace("proxying authenticated request",
			"url", r.URL.String(),
			"method", r.Method,
		)
		reverseProxy.ServeHTTP(w, newR)
	}), nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func getProxyHeaders(userInfo user.Info, requestHeaders http.Header) http.Header {
	newHeaders := requestHeaders.Clone()

	// Leverage client-go's impersonation RoundTripper to set impersonation headers for us in the new
	// request. The client-go RoundTripper not only sets all of the impersonation headers for us, but
	// it also does some helpful escaping of characters that can't go into an HTTP header. To do this,
	// we make a fake call to the impersonation RoundTripper with a fake HTTP request and a delegate
	// RoundTripper that captures the impersonation headers set on the request.
	impersonateConfig := transport.ImpersonationConfig{
		UserName: userInfo.GetName(),
		Groups:   userInfo.GetGroups(),
		Extra:    userInfo.GetExtra(),
	}
	impersonateHeaderSpy := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		newHeaders.Set(transport.ImpersonateUserHeader, r.Header.Get(transport.ImpersonateUserHeader))
		for _, groupHeaderValue := range r.Header.Values(transport.ImpersonateGroupHeader) {
			newHeaders.Add(transport.ImpersonateGroupHeader, groupHeaderValue)
		}
		for headerKey, headerValues := range r.Header {
			if strings.HasPrefix(headerKey, transport.ImpersonateUserExtraHeaderPrefix) {
				for _, headerValue := range headerValues {
					newHeaders.Add(headerKey, headerValue)
				}
			}
		}
		return nil, nil
	})
	fakeReq, _ := http.NewRequestWithContext(context.Background(), "", "", nil)
	//nolint:bodyclose // We return a nil http.Response above, so there is nothing to close.
	_, _ = transport.NewImpersonatingRoundTripper(impersonateConfig, impersonateHeaderSpy).RoundTrip(fakeReq)

	return newHeaders
}

func ensureNoImpersonationHeaders(r *http.Request) error {
	for key := range r.Header {
		if strings.HasPrefix(key, "Impersonate") {
			return fmt.Errorf("%q header already exists", key)
		}
	}

	return nil
}
