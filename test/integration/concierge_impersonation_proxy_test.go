// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	"go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	"go.pinniped.dev/internal/concierge/impersonator"
	"go.pinniped.dev/test/library"
)

// Note that this test supports being run on all of our integration test cluster types:
//   - load balancers not supported, has squid proxy (e.g. kind)
//   - load balancers supported, has squid proxy (e.g. EKS)
//   - load balancers supported, no squid proxy (e.g. GKE)
func TestImpersonationProxy(t *testing.T) {
	env := library.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// Create a client using the admin kubeconfig.
	adminClient := library.NewKubernetesClientset(t)
	adminConciergeClient := library.NewConciergeClientset(t)

	// Create a WebhookAuthenticator.
	authenticator := library.CreateTestWebhookAuthenticator(ctx, t)

	// The address of the ClusterIP service that points at the impersonation proxy's port (used when there is no load balancer).
	proxyServiceEndpoint := fmt.Sprintf("%s-proxy.%s.svc.cluster.local", env.ConciergeAppName, env.ConciergeNamespace)
	expectedProxyServiceEndpointURL := "https://" + proxyServiceEndpoint
	// The error message that will be returned by squid when the impersonation proxy port inside the cluster is not listening.
	serviceUnavailableViaSquidError := fmt.Sprintf(`Get "https://%s/api/v1/namespaces": Service Unavailable`, proxyServiceEndpoint)

	credentialAlmostExpired := func(credential *loginv1alpha1.TokenCredentialRequest) bool {
		pemBlock, _ := pem.Decode([]byte(credential.Status.Credential.ClientCertificateData))
		parsedCredential, err := x509.ParseCertificate(pemBlock.Bytes)
		require.NoError(t, err)
		timeRemaining := time.Until(parsedCredential.NotAfter)
		if timeRemaining < 2*time.Minute {
			t.Logf("The TokenCredentialRequest cred is almost expired and needs to be refreshed. Expires in %s.", timeRemaining)
			return true
		}
		t.Logf("The TokenCredentialRequest cred is good for some more time (%s) so using it.", timeRemaining)
		return false
	}

	var tokenCredentialRequestResponse *loginv1alpha1.TokenCredentialRequest
	refreshCredential := func() *loginv1alpha1.ClusterCredential {
		if tokenCredentialRequestResponse == nil || credentialAlmostExpired(tokenCredentialRequestResponse) {
			var err error
			// Make a TokenCredentialRequest. This can either return a cert signed by the Kube API server's CA (e.g. on kind)
			// or a cert signed by the impersonator's signing CA (e.g. on GKE). Either should be accepted by the impersonation
			// proxy server as a valid authentication.
			//
			// However, we issue short-lived certs, so this cert will only be valid for a few minutes.
			// Cache it until it is almost expired and then refresh it whenever it is close to expired.
			tokenCredentialRequestResponse, err = library.CreateTokenCredentialRequest(ctx, t, loginv1alpha1.TokenCredentialRequestSpec{
				Token:         env.TestUser.Token,
				Authenticator: authenticator,
			})
			require.NoError(t, err)

			require.Empty(t, tokenCredentialRequestResponse.Status.Message) // no error message
			require.NotEmpty(t, tokenCredentialRequestResponse.Status.Credential.ClientCertificateData)
			require.NotEmpty(t, tokenCredentialRequestResponse.Status.Credential.ClientKeyData)

			// At the moment the credential request should not have returned a token. In the future, if we make it return
			// tokens, we should revisit this test's rest config below.
			require.Empty(t, tokenCredentialRequestResponse.Status.Credential.Token)
		}
		return tokenCredentialRequestResponse.Status.Credential
	}

	impersonationProxyRestConfig := func(credential *loginv1alpha1.ClusterCredential, host string, caData []byte, doubleImpersonateUser string) *rest.Config {
		config := rest.Config{
			Host: host,
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: caData == nil,
				CAData:   caData,
				CertData: []byte(credential.ClientCertificateData),
				KeyData:  []byte(credential.ClientKeyData),
			},
			// kubectl would set both the client cert and the token, so we'll do that too.
			// The Kube API server will ignore the token if the client cert successfully authenticates.
			// Only if the client cert is not present or fails to authenticate will it use the token.
			// Historically, it works that way because some web browsers will always send your
			// corporate-assigned client cert even if it is not valid, and it doesn't want to treat
			// that as a failure if you also sent a perfectly good token.
			// We would like the impersonation proxy to imitate that behavior, so we test it here.
			BearerToken: "this is not valid",
		}
		if doubleImpersonateUser != "" {
			config.Impersonate = rest.ImpersonationConfig{UserName: doubleImpersonateUser}
		}
		return &config
	}

	impersonationProxyViaSquidClient := func(proxyURL string, caData []byte, doubleImpersonateUser string) *kubernetes.Clientset {
		t.Helper()
		kubeconfig := impersonationProxyRestConfig(refreshCredential(), proxyURL, caData, doubleImpersonateUser)
		kubeconfig.Proxy = func(req *http.Request) (*url.URL, error) {
			proxyURL, err := url.Parse(env.Proxy)
			require.NoError(t, err)
			t.Logf("passing request for %s through proxy %s", req.URL, proxyURL.String())
			return proxyURL, nil
		}
		impersonationProxyClient, err := kubernetes.NewForConfig(kubeconfig)
		require.NoError(t, err, "unexpected failure from kubernetes.NewForConfig()")
		return impersonationProxyClient
	}

	impersonationProxyViaLoadBalancerClient := func(proxyURL string, caData []byte, doubleImpersonateUser string) *kubernetes.Clientset {
		t.Helper()
		refreshCredential()
		kubeconfig := impersonationProxyRestConfig(refreshCredential(), proxyURL, caData, doubleImpersonateUser)
		impersonationProxyClient, err := kubernetes.NewForConfig(kubeconfig)
		require.NoError(t, err, "unexpected failure from kubernetes.NewForConfig()")
		return impersonationProxyClient
	}

	newImpersonationProxyClient := func(proxyURL string, impersonationProxyCACertPEM []byte, doubleImpersonateUser string) *kubernetes.Clientset {
		if env.HasCapability(library.HasExternalLoadBalancerProvider) {
			return impersonationProxyViaLoadBalancerClient(proxyURL, impersonationProxyCACertPEM, doubleImpersonateUser)
		}
		return impersonationProxyViaSquidClient(proxyURL, impersonationProxyCACertPEM, doubleImpersonateUser)
	}

	oldConfigMap, err := adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Get(ctx, impersonationProxyConfigMapName(env), metav1.GetOptions{})
	if !k8serrors.IsNotFound(err) {
		require.NoError(t, err) // other errors aside from NotFound are unexpected
		t.Logf("stashing a pre-existing configmap %s", oldConfigMap.Name)
		require.NoError(t, adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Delete(ctx, impersonationProxyConfigMapName(env), metav1.DeleteOptions{}))
	}
	// At the end of the test, clean up the ConfigMap.
	t.Cleanup(func() {
		ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		// Delete any version that was created by this test.
		t.Logf("cleaning up configmap at end of test %s", impersonationProxyConfigMapName(env))
		err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Delete(ctx, impersonationProxyConfigMapName(env), metav1.DeleteOptions{})
		if !k8serrors.IsNotFound(err) {
			require.NoError(t, err) // only not found errors are acceptable
		}

		// Only recreate it if it already existed at the start of this test.
		if len(oldConfigMap.Data) != 0 {
			t.Log(oldConfigMap)
			oldConfigMap.UID = "" // cant have a UID yet
			oldConfigMap.ResourceVersion = ""
			t.Logf("restoring a pre-existing configmap %s", oldConfigMap.Name)
			_, err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Create(ctx, oldConfigMap, metav1.CreateOptions{})
			require.NoError(t, err)
		}
	})

	if env.HasCapability(library.HasExternalLoadBalancerProvider) { //nolint:nestif // come on... it's just a test
		// Check that load balancer has been automatically created by the impersonator's "auto" mode.
		library.RequireEventuallyWithoutError(t, func() (bool, error) {
			return hasImpersonationProxyLoadBalancerService(ctx, env, adminClient)
		}, 30*time.Second, 500*time.Millisecond)
	} else {
		require.NotEmpty(t, env.Proxy,
			"test cluster does not support load balancers but also doesn't have a squid proxy... "+
				"this is not a supported configuration for test clusters")

		// Check that no load balancer has been created by the impersonator's "auto" mode.
		library.RequireNeverWithoutError(t, func() (bool, error) {
			return hasImpersonationProxyLoadBalancerService(ctx, env, adminClient)
		}, 10*time.Second, 500*time.Millisecond)

		// Check that we can't use the impersonation proxy to execute kubectl commands yet.
		_, err = impersonationProxyViaSquidClient(expectedProxyServiceEndpointURL, nil, "").CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		require.EqualError(t, err, serviceUnavailableViaSquidError)

		// Create configuration to make the impersonation proxy turn on with a hard coded endpoint (without a load balancer).
		configMap := configMapForConfig(t, env, impersonator.Config{
			Mode:     impersonator.ModeEnabled,
			Endpoint: proxyServiceEndpoint,
		})
		t.Logf("creating configmap %s", configMap.Name)
		_, err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Create(ctx, &configMap, metav1.CreateOptions{})
		require.NoError(t, err)
	}

	// At this point the impersonator should be starting/running. When it is ready, the CredentialIssuer's
	// strategies array should be updated to include a successful impersonation strategy which can be used
	// to discover the impersonator's URL and CA certificate. Until it has finished starting, it may not be included
	// in the strategies array or it may be included in an error state. It can be in an error state for
	// awhile when it is waiting for the load balancer to be assigned an ip/hostname.
	impersonationProxyURL, impersonationProxyCACertPEM := performImpersonatorDiscovery(ctx, t, env, adminConciergeClient)
	if !env.HasCapability(library.HasExternalLoadBalancerProvider) {
		// In this case, we specified the endpoint in the configmap, so check that it was reported correctly in the CredentialIssuer.
		require.Equal(t, "https://"+proxyServiceEndpoint, impersonationProxyURL)
	}

	// Because our credentials expire so quickly, we'll always use a new client, to give us a chance to refresh our
	// credentials before they expire. Create a closure to capture the arguments to newImpersonationProxyClient
	// so we don't have to keep repeating them.
	// This client performs TLS checks, so it also provides test coverage that the impersonation proxy server is generating TLS certs correctly.
	impersonationProxyClient := func() *kubernetes.Clientset {
		return newImpersonationProxyClient(impersonationProxyURL, impersonationProxyCACertPEM, "")
	}

	// Test that the user can perform basic actions through the client with their username and group membership
	// influencing RBAC checks correctly.
	t.Run(
		"access as user",
		library.AccessAsUserTest(ctx, env.TestUser.ExpectedUsername, impersonationProxyClient()),
	)
	for _, group := range env.TestUser.ExpectedGroups {
		group := group
		t.Run(
			"access as group "+group,
			library.AccessAsGroupTest(ctx, group, impersonationProxyClient()),
		)
	}

	// Try more Kube API verbs through the impersonation proxy.
	t.Run("watching all the basic verbs", func(t *testing.T) {
		// Create a namespace, because it will be easier to exercise "deletecollection" if we have a namespace.
		namespace, err := adminClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "impersonation-integration-test-"},
		}, metav1.CreateOptions{})
		require.NoError(t, err)
		// Schedule the namespace for cleanup.
		t.Cleanup(func() {
			t.Logf("cleaning up test namespace %s", namespace.Name)
			err = adminClient.CoreV1().Namespaces().Delete(context.Background(), namespace.Name, metav1.DeleteOptions{})
			require.NoError(t, err)
		})

		// Create an RBAC rule to allow this user to read/write everything.
		library.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: env.TestUser.ExpectedUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "cluster-admin"},
		)
		// Wait for the above RBAC rule to take effect.
		library.WaitForUserToHaveAccess(t, env.TestUser.ExpectedUsername, []string{}, &v1.ResourceAttributes{
			Namespace: namespace.Name, Verb: "create", Group: "", Version: "v1", Resource: "configmaps",
		})

		// Create and start informer to exercise the "watch" verb for us.
		informerFactory := k8sinformers.NewSharedInformerFactoryWithOptions(
			impersonationProxyClient(),
			0,
			k8sinformers.WithNamespace(namespace.Name))
		informer := informerFactory.Core().V1().ConfigMaps()
		informer.Informer() // makes sure that the informer will cache
		stopChannel := make(chan struct{})
		informerFactory.Start(stopChannel)
		t.Cleanup(func() {
			// Shut down the informer.
			close(stopChannel)
		})
		informerFactory.WaitForCacheSync(ctx.Done())

		// Use labels on our created ConfigMaps to avoid accidentally listing other ConfigMaps that might
		// exist in the namespace. In Kube 1.20+ there is a default ConfigMap in every namespace.
		configMapLabels := labels.Set{
			"pinniped.dev/testConfigMap": library.RandHex(t, 8),
		}

		// Test "create" verb through the impersonation proxy.
		_, err = impersonationProxyClient().CoreV1().ConfigMaps(namespace.Name).Create(ctx,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap-1", Labels: configMapLabels}},
			metav1.CreateOptions{},
		)
		require.NoError(t, err)
		_, err = impersonationProxyClient().CoreV1().ConfigMaps(namespace.Name).Create(ctx,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap-2", Labels: configMapLabels}},
			metav1.CreateOptions{},
		)
		require.NoError(t, err)
		_, err = impersonationProxyClient().CoreV1().ConfigMaps(namespace.Name).Create(ctx,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap-3", Labels: configMapLabels}},
			metav1.CreateOptions{},
		)
		require.NoError(t, err)

		// Make sure that all of the created ConfigMaps show up in the informer's cache to
		// demonstrate that the informer's "watch" verb is working through the impersonation proxy.
		require.Eventually(t, func() bool {
			_, err1 := informer.Lister().ConfigMaps(namespace.Name).Get("configmap-1")
			_, err2 := informer.Lister().ConfigMaps(namespace.Name).Get("configmap-2")
			_, err3 := informer.Lister().ConfigMaps(namespace.Name).Get("configmap-3")
			return err1 == nil && err2 == nil && err3 == nil
		}, 10*time.Second, 50*time.Millisecond)

		// Test "get" verb through the impersonation proxy.
		configMap3, err := impersonationProxyClient().CoreV1().ConfigMaps(namespace.Name).Get(ctx, "configmap-3", metav1.GetOptions{})
		require.NoError(t, err)

		// Test "list" verb through the impersonation proxy.
		listResult, err := impersonationProxyClient().CoreV1().ConfigMaps(namespace.Name).List(ctx, metav1.ListOptions{
			LabelSelector: configMapLabels.String(),
		})
		require.NoError(t, err)
		require.Len(t, listResult.Items, 3)

		// Test "update" verb through the impersonation proxy.
		configMap3.Data = map[string]string{"foo": "bar"}
		updateResult, err := impersonationProxyClient().CoreV1().ConfigMaps(namespace.Name).Update(ctx, configMap3, metav1.UpdateOptions{})
		require.NoError(t, err)
		require.Equal(t, "bar", updateResult.Data["foo"])

		// Make sure that the updated ConfigMap shows up in the informer's cache.
		require.Eventually(t, func() bool {
			configMap, err := informer.Lister().ConfigMaps(namespace.Name).Get("configmap-3")
			return err == nil && configMap.Data["foo"] == "bar"
		}, 10*time.Second, 50*time.Millisecond)

		// Test "patch" verb through the impersonation proxy.
		patchResult, err := impersonationProxyClient().CoreV1().ConfigMaps(namespace.Name).Patch(ctx,
			"configmap-3",
			types.MergePatchType,
			[]byte(`{"data":{"baz":"42"}}`),
			metav1.PatchOptions{},
		)
		require.NoError(t, err)
		require.Equal(t, "bar", patchResult.Data["foo"])
		require.Equal(t, "42", patchResult.Data["baz"])

		// Make sure that the patched ConfigMap shows up in the informer's cache.
		require.Eventually(t, func() bool {
			configMap, err := informer.Lister().ConfigMaps(namespace.Name).Get("configmap-3")
			return err == nil && configMap.Data["foo"] == "bar" && configMap.Data["baz"] == "42"
		}, 10*time.Second, 50*time.Millisecond)

		// Test "delete" verb through the impersonation proxy.
		err = impersonationProxyClient().CoreV1().ConfigMaps(namespace.Name).Delete(ctx, "configmap-3", metav1.DeleteOptions{})
		require.NoError(t, err)

		// Make sure that the deleted ConfigMap shows up in the informer's cache.
		require.Eventually(t, func() bool {
			_, getErr := informer.Lister().ConfigMaps(namespace.Name).Get("configmap-3")
			list, listErr := informer.Lister().ConfigMaps(namespace.Name).List(configMapLabels.AsSelector())
			return k8serrors.IsNotFound(getErr) && listErr == nil && len(list) == 2
		}, 10*time.Second, 50*time.Millisecond)

		// Test "deletecollection" verb through the impersonation proxy.
		err = impersonationProxyClient().CoreV1().ConfigMaps(namespace.Name).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
		require.NoError(t, err)

		// Make sure that the deleted ConfigMaps shows up in the informer's cache.
		require.Eventually(t, func() bool {
			list, listErr := informer.Lister().ConfigMaps(namespace.Name).List(configMapLabels.AsSelector())
			return listErr == nil && len(list) == 0
		}, 10*time.Second, 50*time.Millisecond)

		// There should be no ConfigMaps left.
		listResult, err = impersonationProxyClient().CoreV1().ConfigMaps(namespace.Name).List(ctx, metav1.ListOptions{
			LabelSelector: configMapLabels.String(),
		})
		require.NoError(t, err)
		require.Len(t, listResult.Items, 0)
	})

	t.Run("double impersonation is blocked", func(t *testing.T) {
		// Create an RBAC rule to allow this user to read/write everything.
		library.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: env.TestUser.ExpectedUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "edit"},
		)
		// Wait for the above RBAC rule to take effect.
		library.WaitForUserToHaveAccess(t, env.TestUser.ExpectedUsername, []string{}, &v1.ResourceAttributes{
			Namespace: env.ConciergeNamespace, Verb: "get", Group: "", Version: "v1", Resource: "secrets",
		})

		// Make a client which will send requests through the impersonation proxy and will also add
		// impersonate headers to the request.
		doubleImpersonationClient := newImpersonationProxyClient(impersonationProxyURL, impersonationProxyCACertPEM, "other-user-to-impersonate")

		// Check that we can get some resource through the impersonation proxy without any impersonation headers on the request.
		// We could use any resource for this, but we happen to know that this one should exist.
		_, err = impersonationProxyClient().CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
		require.NoError(t, err)

		// Now we'll see what happens when we add an impersonation header to the request. This should generate a
		// request similar to the one above, except that it will have an impersonation header.
		_, err = doubleImpersonationClient.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
		// Double impersonation is not supported yet, so we should get an error.
		require.EqualError(t, err, fmt.Sprintf(
			`users "other-user-to-impersonate" is forbidden: `+
				`User "%s" cannot impersonate resource "users" in API group "" at the cluster scope: `+
				`impersonation is not allowed or invalid verb`,
			env.TestUser.ExpectedUsername))
	})

	// Update configuration to force the proxy to disabled mode
	configMap := configMapForConfig(t, env, impersonator.Config{Mode: impersonator.ModeDisabled})
	if env.HasCapability(library.HasExternalLoadBalancerProvider) {
		t.Logf("creating configmap %s", configMap.Name)
		_, err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Create(ctx, &configMap, metav1.CreateOptions{})
		require.NoError(t, err)
	} else {
		t.Logf("updating configmap %s", configMap.Name)
		_, err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Update(ctx, &configMap, metav1.UpdateOptions{})
		require.NoError(t, err)
	}

	if env.HasCapability(library.HasExternalLoadBalancerProvider) {
		// The load balancer should have been deleted when we disabled the impersonation proxy.
		// Note that this can take kind of a long time on real cloud providers (e.g. ~22 seconds on EKS).
		library.RequireEventuallyWithoutError(t, func() (bool, error) {
			hasService, err := hasImpersonationProxyLoadBalancerService(ctx, env, adminClient)
			return !hasService, err
		}, 2*time.Minute, 500*time.Millisecond)
	}

	// Check that the impersonation proxy port has shut down.
	// Ideally we could always check that the impersonation proxy's port has shut down, but on clusters where we
	// do not run the squid proxy we have no easy way to see beyond the load balancer to see inside the cluster,
	// so we'll skip this check on clusters which have load balancers but don't run the squid proxy.
	// The other cluster types that do run the squid proxy will give us sufficient coverage here.
	if env.Proxy != "" {
		require.Eventually(t, func() bool {
			// It's okay if this returns RBAC errors because this user has no role bindings.
			// What we want to see is that the proxy eventually shuts down entirely.
			_, err = impersonationProxyViaSquidClient(expectedProxyServiceEndpointURL, nil, "").CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			return err.Error() == serviceUnavailableViaSquidError
		}, 20*time.Second, 500*time.Millisecond)
	}

	// Check that the generated TLS cert Secret was deleted by the controller because it's supposed to clean this up
	// when we disable the impersonator.
	require.Eventually(t, func() bool {
		_, err = adminClient.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
		return k8serrors.IsNotFound(err)
	}, 10*time.Second, 250*time.Millisecond)

	// Check that the generated CA cert Secret was not deleted by the controller because it's supposed to keep this
	// around in case we decide to later re-enable the impersonator. We want to avoid generating new CA certs when
	// possible because they make their way into kubeconfigs on client machines.
	_, err = adminClient.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyCASecretName(env), metav1.GetOptions{})
	require.NoError(t, err)

	// At this point the impersonator should be stopped. The CredentialIssuer's strategies array should be updated to
	// include an unsuccessful impersonation strategy saying that it was manually configured to be disabled.
	requireDisabledByConfigurationStrategy(ctx, t, env, adminConciergeClient)
}

func performImpersonatorDiscovery(ctx context.Context, t *testing.T, env *library.TestEnv, adminConciergeClient versioned.Interface) (string, []byte) {
	t.Helper()
	var impersonationProxyURL string
	var impersonationProxyCACertPEM []byte

	t.Log("Waiting for CredentialIssuer strategy to be successful")

	library.RequireEventuallyWithoutError(t, func() (bool, error) {
		credentialIssuer, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
		if err != nil || credentialIssuer.Status.Strategies == nil {
			t.Log("Did not find any CredentialIssuer with any strategies")
			return false, nil // didn't find it, but keep trying
		}
		for _, strategy := range credentialIssuer.Status.Strategies {
			// There will be other strategy types in the list, so ignore those.
			if strategy.Type == v1alpha1.ImpersonationProxyStrategyType && strategy.Status == v1alpha1.SuccessStrategyStatus { //nolint:nestif
				if strategy.Frontend == nil {
					return false, fmt.Errorf("did not find a Frontend") // unexpected, fail the test
				}
				if strategy.Frontend.ImpersonationProxyInfo == nil {
					return false, fmt.Errorf("did not find an ImpersonationProxyInfo") // unexpected, fail the test
				}
				impersonationProxyURL = strategy.Frontend.ImpersonationProxyInfo.Endpoint
				impersonationProxyCACertPEM, err = base64.StdEncoding.DecodeString(strategy.Frontend.ImpersonationProxyInfo.CertificateAuthorityData)
				if err != nil {
					return false, err // unexpected, fail the test
				}
				return true, nil // found it, continue the test!
			} else if strategy.Type == v1alpha1.ImpersonationProxyStrategyType {
				t.Logf("Waiting for successful impersonation proxy strategy on %s: found status %s with reason %s and message: %s",
					credentialIssuerName(env), strategy.Status, strategy.Reason, strategy.Message)
				if strategy.Reason == v1alpha1.ErrorDuringSetupStrategyReason {
					// The server encountered an unexpected error while starting the impersonator, so fail the test fast.
					return false, fmt.Errorf("found impersonation strategy in %s state with message: %s", strategy.Reason, strategy.Message)
				}
			}
		}
		t.Log("Did not find any impersonation proxy strategy on CredentialIssuer")
		return false, nil // didn't find it, but keep trying
	}, 10*time.Minute, 10*time.Second)

	t.Log("Found successful CredentialIssuer strategy")
	return impersonationProxyURL, impersonationProxyCACertPEM
}

func requireDisabledByConfigurationStrategy(ctx context.Context, t *testing.T, env *library.TestEnv, adminConciergeClient versioned.Interface) {
	t.Helper()

	library.RequireEventuallyWithoutError(t, func() (bool, error) {
		credentialIssuer, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
		if err != nil || credentialIssuer.Status.Strategies == nil {
			t.Log("Did not find any CredentialIssuer with any strategies")
			return false, nil // didn't find it, but keep trying
		}
		for _, strategy := range credentialIssuer.Status.Strategies {
			// There will be other strategy types in the list, so ignore those.
			if strategy.Type == v1alpha1.ImpersonationProxyStrategyType &&
				strategy.Status == v1alpha1.ErrorStrategyStatus &&
				strategy.Reason == v1alpha1.DisabledStrategyReason { //nolint:nestif
				return true, nil // found it, continue the test!
			} else if strategy.Type == v1alpha1.ImpersonationProxyStrategyType {
				t.Logf("Waiting for disabled impersonation proxy strategy on %s: found status %s with reason %s and message: %s",
					credentialIssuerName(env), strategy.Status, strategy.Reason, strategy.Message)
				if strategy.Reason == v1alpha1.ErrorDuringSetupStrategyReason {
					// The server encountered an unexpected error while stopping the impersonator, so fail the test fast.
					return false, fmt.Errorf("found impersonation strategy in %s state with message: %s", strategy.Reason, strategy.Message)
				}
			}
		}
		t.Log("Did not find any impersonation proxy strategy on CredentialIssuer")
		return false, nil // didn't find it, but keep trying
	}, 1*time.Minute, 500*time.Millisecond)
}

func configMapForConfig(t *testing.T, env *library.TestEnv, config impersonator.Config) corev1.ConfigMap {
	t.Helper()
	configString, err := yaml.Marshal(config)
	require.NoError(t, err)
	configMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: impersonationProxyConfigMapName(env),
		},
		Data: map[string]string{
			"config.yaml": string(configString),
		}}
	return configMap
}

func hasImpersonationProxyLoadBalancerService(ctx context.Context, env *library.TestEnv, client kubernetes.Interface) (bool, error) {
	service, err := client.CoreV1().Services(env.ConciergeNamespace).Get(ctx, impersonationProxyLoadBalancerName(env), metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return service.Spec.Type == corev1.ServiceTypeLoadBalancer, nil
}

func impersonationProxyConfigMapName(env *library.TestEnv) string {
	return env.ConciergeAppName + "-impersonation-proxy-config"
}

func impersonationProxyTLSSecretName(env *library.TestEnv) string {
	return env.ConciergeAppName + "-impersonation-proxy-tls-serving-certificate"
}

func impersonationProxyCASecretName(env *library.TestEnv) string {
	return env.ConciergeAppName + "-impersonation-proxy-ca-certificate"
}

func impersonationProxyLoadBalancerName(env *library.TestEnv) string {
	return env.ConciergeAppName + "-impersonation-proxy-load-balancer"
}

func credentialIssuerName(env *library.TestEnv) string {
	return env.ConciergeAppName + "-config"
}
