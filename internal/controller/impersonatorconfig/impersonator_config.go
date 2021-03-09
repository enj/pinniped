// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonatorconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"go.pinniped.dev/internal/controller/apicerts"

	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"

	"go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/clusterhost"
	"go.pinniped.dev/internal/concierge/impersonator"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/issuerconfig"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/plog"
)

const (
	impersonationProxyPort = 8444
	defaultHTTPSPort       = 443
	oneYear                = 100 * 365 * 24 * time.Hour
	caCommonName           = "Pinniped Impersonation Proxy CA"
	caCrtKey               = "ca.crt"
	caKeyKey               = "ca.key"
	appLabelKey            = "app"
)

type impersonatorConfigController struct {
	namespace                        string
	configMapResourceName            string
	credentialIssuerResourceName     string
	generatedLoadBalancerServiceName string
	tlsSecretName                    string
	caSecretName                     string
	impersonationSignerSecretName    string

	k8sClient         kubernetes.Interface
	pinnipedAPIClient pinnipedclientset.Interface

	configMapsInformer corev1informers.ConfigMapInformer
	servicesInformer   corev1informers.ServiceInformer
	secretsInformer    corev1informers.SecretInformer

	labels                           map[string]string
	clock                            clock.Clock
	impersonationSigningCertProvider dynamiccert.Provider
	impersonatorFunc                 impersonator.FactoryFunc

	hasControlPlaneNodes              *bool
	serverStopCh                      chan struct{}
	tlsServingCertDynamicCertProvider dynamiccert.Provider
}

type StartTLSListenerFunc func(network, listenAddress string, config *tls.Config) (net.Listener, error)

func NewImpersonatorConfigController(
	namespace string,
	configMapResourceName string,
	credentialIssuerResourceName string,
	k8sClient kubernetes.Interface,
	pinnipedAPIClient pinnipedclientset.Interface,
	configMapsInformer corev1informers.ConfigMapInformer,
	servicesInformer corev1informers.ServiceInformer,
	secretsInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	withInitialEvent pinnipedcontroller.WithInitialEventOptionFunc,
	generatedLoadBalancerServiceName string,
	tlsSecretName string,
	caSecretName string,
	labels map[string]string,
	clock clock.Clock,
	impersonatorFunc impersonator.FactoryFunc,
	impersonationSignerSecretName string,
	impersonationSigningCertProvider dynamiccert.Provider,
) controllerlib.Controller {
	secretNames := sets.NewString(tlsSecretName, caSecretName, impersonationSignerSecretName)
	return controllerlib.New(
		controllerlib.Config{
			Name: "impersonator-config-controller",
			Syncer: &impersonatorConfigController{
				namespace:                         namespace,
				configMapResourceName:             configMapResourceName,
				credentialIssuerResourceName:      credentialIssuerResourceName,
				generatedLoadBalancerServiceName:  generatedLoadBalancerServiceName,
				tlsSecretName:                     tlsSecretName,
				caSecretName:                      caSecretName,
				impersonationSignerSecretName:     impersonationSignerSecretName,
				k8sClient:                         k8sClient,
				pinnipedAPIClient:                 pinnipedAPIClient,
				configMapsInformer:                configMapsInformer,
				servicesInformer:                  servicesInformer,
				secretsInformer:                   secretsInformer,
				labels:                            labels,
				clock:                             clock,
				impersonationSigningCertProvider:  impersonationSigningCertProvider,
				impersonatorFunc:                  impersonatorFunc,
				tlsServingCertDynamicCertProvider: dynamiccert.New(),
			},
		},
		withInformer(
			configMapsInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(configMapResourceName, namespace),
			controllerlib.InformerOption{},
		),
		withInformer(
			servicesInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(generatedLoadBalancerServiceName, namespace),
			controllerlib.InformerOption{},
		),
		withInformer(
			secretsInformer,
			pinnipedcontroller.SimpleFilter(func(obj metav1.Object) bool {
				return obj.GetNamespace() == namespace && secretNames.Has(obj.GetName())
			}, nil),
			controllerlib.InformerOption{},
		),
		// Be sure to run once even if the ConfigMap that the informer is watching doesn't exist so we can implement
		// the default configuration behavior.
		withInitialEvent(controllerlib.Key{
			Namespace: namespace,
			Name:      configMapResourceName,
		}),
	)
}

func (c *impersonatorConfigController) Sync(syncCtx controllerlib.Context) error {
	plog.Debug("Starting impersonatorConfigController Sync")

	strategy, err := c.doSync(syncCtx.Context)

	if err != nil {
		strategy = &v1alpha1.CredentialIssuerStrategy{
			Type:           v1alpha1.ImpersonationProxyStrategyType,
			Status:         v1alpha1.ErrorStrategyStatus,
			Reason:         v1alpha1.ErrorDuringSetupStrategyReason,
			Message:        err.Error(),
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
		}
		// The impersonator is not ready, so clear the signer CA from the dynamic provider.
		c.clearSignerCA()
	}

	updateStrategyErr := c.updateStrategy(syncCtx.Context, strategy)
	if updateStrategyErr != nil {
		plog.Error("error while updating the CredentialIssuer status", err)
		if err == nil {
			err = updateStrategyErr
		}
	}

	if err == nil {
		plog.Debug("Successfully finished impersonatorConfigController Sync")
	}
	return err
}

type certNameInfo struct {
	// ready will be true when the certificate name information is known.
	// ready will be false when it is pending because we are waiting for a load balancer to get assigned an ip/hostname.
	// When false, the other fields in this struct should not be considered meaningful and may be zero values.
	ready bool

	// The IP address or hostname which was selected to be used as the name in the cert.
	// Either selectedIP or selectedHostname will be set, but not both.
	selectedIP       net.IP
	selectedHostname string

	// The name of the endpoint to which a client should connect to talk to the impersonator.
	// This may be a hostname or an IP, and may include a port number.
	clientEndpoint string
}

func (c *impersonatorConfigController) doSync(ctx context.Context) (*v1alpha1.CredentialIssuerStrategy, error) {
	config, err := c.loadImpersonationProxyConfiguration()
	if err != nil {
		return nil, err
	}

	// Make a live API call to avoid the cost of having an informer watch all node changes on the cluster,
	// since there could be lots and we don't especially care about node changes.
	// Once we have concluded that there is or is not a visible control plane, then cache that decision
	// to avoid listing nodes very often.
	if c.hasControlPlaneNodes == nil {
		hasControlPlaneNodes, err := clusterhost.New(c.k8sClient).HasControlPlaneNodes(ctx)
		if err != nil {
			return nil, err
		}
		c.hasControlPlaneNodes = &hasControlPlaneNodes
		plog.Debug("Queried for control plane nodes", "foundControlPlaneNodes", hasControlPlaneNodes)
	}

	if c.shouldHaveImpersonator(config) {
		if err = c.ensureImpersonatorIsStarted(); err != nil {
			return nil, err
		}
	} else {
		c.ensureImpersonatorIsStopped()
	}

	if c.shouldHaveLoadBalancer(config) {
		if err = c.ensureLoadBalancerIsStarted(ctx); err != nil {
			return nil, err
		}
	} else {
		if err = c.ensureLoadBalancerIsStopped(ctx); err != nil {
			return nil, err
		}
	}

	nameInfo, err := c.findDesiredTLSCertificateName(config)
	if err != nil {
		return nil, err
	}

	var impersonationCA *certauthority.CA
	if c.shouldHaveTLSSecret(config) {
		if impersonationCA, err = c.ensureCASecretIsCreated(ctx); err != nil {
			return nil, err
		}
		if err = c.ensureTLSSecret(ctx, nameInfo, impersonationCA); err != nil {
			return nil, err
		}
	} else if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
		return nil, err
	}

	credentialIssuerStrategyResult := c.doSyncResult(nameInfo, config, impersonationCA)

	if err = c.loadSignerCA(credentialIssuerStrategyResult.Status); err != nil {
		return nil, err
	}

	return credentialIssuerStrategyResult, nil
}

func (c *impersonatorConfigController) loadImpersonationProxyConfiguration() (*impersonator.Config, error) {
	configMap, err := c.configMapsInformer.Lister().ConfigMaps(c.namespace).Get(c.configMapResourceName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return nil, fmt.Errorf("failed to get %s/%s configmap: %w", c.namespace, c.configMapResourceName, err)
	}

	var config *impersonator.Config
	if notFound {
		plog.Info("Did not find impersonation proxy config: using default config values",
			"configmap", c.configMapResourceName,
			"namespace", c.namespace,
		)
		config = impersonator.NewConfig() // use default configuration options
	} else {
		config, err = impersonator.ConfigFromConfigMap(configMap)
		if err != nil {
			return nil, fmt.Errorf("invalid impersonator configuration: %v", err)
		}
		plog.Info("Read impersonation proxy config",
			"configmap", c.configMapResourceName,
			"namespace", c.namespace,
		)
	}

	return config, nil
}

func (c *impersonatorConfigController) shouldHaveImpersonator(config *impersonator.Config) bool {
	return c.enabledByAutoMode(config) || config.Mode == impersonator.ModeEnabled
}

func (c *impersonatorConfigController) enabledByAutoMode(config *impersonator.Config) bool {
	return config.Mode == impersonator.ModeAuto && !*c.hasControlPlaneNodes
}

func (c *impersonatorConfigController) disabledByAutoMode(config *impersonator.Config) bool {
	return config.Mode == impersonator.ModeAuto && *c.hasControlPlaneNodes
}

func (c *impersonatorConfigController) disabledExplicitly(config *impersonator.Config) bool {
	return config.Mode == impersonator.ModeDisabled
}

func (c *impersonatorConfigController) shouldHaveLoadBalancer(config *impersonator.Config) bool {
	return c.shouldHaveImpersonator(config) && !config.HasEndpoint()
}

func (c *impersonatorConfigController) shouldHaveTLSSecret(config *impersonator.Config) bool {
	return c.shouldHaveImpersonator(config)
}

func (c *impersonatorConfigController) updateStrategy(ctx context.Context, strategy *v1alpha1.CredentialIssuerStrategy) error {
	return issuerconfig.UpdateStrategy(ctx, c.credentialIssuerResourceName, c.labels, c.pinnipedAPIClient, *strategy)
}

func (c *impersonatorConfigController) loadBalancerExists() (bool, error) {
	_, err := c.servicesInformer.Lister().Services(c.namespace).Get(c.generatedLoadBalancerServiceName)
	notFound := k8serrors.IsNotFound(err)
	if notFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *impersonatorConfigController) tlsSecretExists() (bool, *v1.Secret, error) {
	secret, err := c.secretsInformer.Lister().Secrets(c.namespace).Get(c.tlsSecretName)
	notFound := k8serrors.IsNotFound(err)
	if notFound {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	return true, secret, nil
}

func (c *impersonatorConfigController) ensureImpersonatorIsStarted() error {
	if c.serverStopCh != nil {
		return nil
	}

	plog.Info("Starting impersonation proxy", "port", impersonationProxyPort)
	startImpersonatorFunc, err := c.impersonatorFunc(
		impersonationProxyPort,
		c.tlsServingCertDynamicCertProvider,
		nil, // TODO give a ca provider based on c.impersonationSigningCertProvider
	)
	if err != nil {
		return err
	}
	c.serverStopCh = make(chan struct{})
	err = startImpersonatorFunc(c.serverStopCh)
	if err != nil {
		return err
	}
	return nil
}

func (c *impersonatorConfigController) ensureImpersonatorIsStopped() {
	if c.serverStopCh == nil {
		return
	}

	plog.Info("Stopping impersonation proxy", "port", impersonationProxyPort)
	close(c.serverStopCh)
	c.serverStopCh = nil
}

func (c *impersonatorConfigController) ensureLoadBalancerIsStarted(ctx context.Context) error {
	running, err := c.loadBalancerExists()
	if err != nil {
		return err
	}
	if running {
		return nil
	}
	appNameLabel := c.labels[appLabelKey]
	loadBalancer := v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{
					TargetPort: intstr.FromInt(impersonationProxyPort),
					Port:       defaultHTTPSPort,
					Protocol:   v1.ProtocolTCP,
				},
			},
			Selector: map[string]string{appLabelKey: appNameLabel},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.generatedLoadBalancerServiceName,
			Namespace: c.namespace,
			Labels:    c.labels,
		},
	}
	plog.Info("creating load balancer for impersonation proxy",
		"service", c.generatedLoadBalancerServiceName,
		"namespace", c.namespace)
	_, err = c.k8sClient.CoreV1().Services(c.namespace).Create(ctx, &loadBalancer, metav1.CreateOptions{})
	return err
}

func (c *impersonatorConfigController) ensureLoadBalancerIsStopped(ctx context.Context) error {
	running, err := c.loadBalancerExists()
	if err != nil {
		return err
	}
	if !running {
		return nil
	}

	plog.Info("Deleting load balancer for impersonation proxy",
		"service", c.generatedLoadBalancerServiceName,
		"namespace", c.namespace)
	return c.k8sClient.CoreV1().Services(c.namespace).Delete(ctx, c.generatedLoadBalancerServiceName, metav1.DeleteOptions{})
}

func (c *impersonatorConfigController) ensureTLSSecret(ctx context.Context, nameInfo *certNameInfo, ca *certauthority.CA) error {
	secretFromInformer, err := c.secretsInformer.Lister().Secrets(c.namespace).Get(c.tlsSecretName)
	notFound := k8serrors.IsNotFound(err)
	if !notFound && err != nil {
		return err
	}

	if !notFound {
		secretWasDeleted, err := c.deleteTLSSecretWhenCertificateDoesNotMatchDesiredState(ctx, nameInfo, ca, secretFromInformer)
		if err != nil {
			return err
		}
		// If it was deleted by the above call, then set it to nil. This allows us to avoid waiting
		// for the informer cache to update before deciding to proceed to create the new Secret below.
		if secretWasDeleted {
			secretFromInformer = nil
		}
	}

	return c.ensureTLSSecretIsCreatedAndLoaded(ctx, nameInfo, secretFromInformer, ca)
}

func (c *impersonatorConfigController) deleteTLSSecretWhenCertificateDoesNotMatchDesiredState(ctx context.Context, nameInfo *certNameInfo, ca *certauthority.CA, secret *v1.Secret) (bool, error) {
	certPEM := secret.Data[v1.TLSCertKey]
	block, _ := pem.Decode(certPEM)
	if block == nil {
		plog.Warning("Found missing or not PEM-encoded data in TLS Secret",
			"invalidCertPEM", string(certPEM),
			"secret", c.tlsSecretName,
			"namespace", c.namespace)
		deleteErr := c.ensureTLSSecretIsRemoved(ctx)
		if deleteErr != nil {
			return false, fmt.Errorf("found missing or not PEM-encoded data in TLS Secret, but got error while deleting it: %w", deleteErr)
		}
		return true, nil
	}

	actualCertFromSecret, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		plog.Error("Found invalid PEM data in TLS Secret", err,
			"invalidCertPEM", string(certPEM),
			"secret", c.tlsSecretName,
			"namespace", c.namespace)
		if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
			return false, fmt.Errorf("PEM data represented an invalid cert, but got error while deleting it: %w", err)
		}
		return true, nil
	}

	keyPEM := secret.Data[v1.TLSPrivateKeyKey]
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		plog.Error("Found invalid private key PEM data in TLS Secret", err,
			"secret", c.tlsSecretName,
			"namespace", c.namespace)
		if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
			return false, fmt.Errorf("cert had an invalid private key, but got error while deleting it: %w", err)
		}
		return true, nil
	}

	opts := x509.VerifyOptions{Roots: ca.Pool()}
	if _, err = actualCertFromSecret.Verify(opts); err != nil {
		// The TLS cert was not signed by the current CA. Since they are mismatched, delete the TLS cert
		// so we can recreate it using the current CA.
		if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
			return false, err
		}
		return true, nil
	}

	if !nameInfo.ready {
		// We currently have a secret but we are waiting for a load balancer to be assigned an ingress, so
		// our current secret must be old/unwanted.
		if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
			return false, err
		}
		return true, nil
	}

	actualIPs := actualCertFromSecret.IPAddresses
	actualHostnames := actualCertFromSecret.DNSNames
	plog.Info("Checking TLS certificate names",
		"desiredIP", nameInfo.selectedIP,
		"desiredHostname", nameInfo.selectedHostname,
		"actualIPs", actualIPs,
		"actualHostnames", actualHostnames,
		"secret", c.tlsSecretName,
		"namespace", c.namespace)

	if certHostnameAndIPMatchDesiredState(nameInfo.selectedIP, actualIPs, nameInfo.selectedHostname, actualHostnames) {
		// The cert already matches the desired state, so there is no need to delete/recreate it.
		return false, nil
	}

	if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func certHostnameAndIPMatchDesiredState(desiredIP net.IP, actualIPs []net.IP, desiredHostname string, actualHostnames []string) bool {
	if desiredIP != nil && len(actualIPs) == 1 && desiredIP.Equal(actualIPs[0]) && len(actualHostnames) == 0 {
		return true
	}
	if desiredHostname != "" && len(actualHostnames) == 1 && desiredHostname == actualHostnames[0] && len(actualIPs) == 0 {
		return true
	}
	return false
}

func (c *impersonatorConfigController) ensureTLSSecretIsCreatedAndLoaded(ctx context.Context, nameInfo *certNameInfo, secret *v1.Secret, ca *certauthority.CA) error {
	if secret != nil {
		err := c.loadTLSCertFromSecret(secret)
		if err != nil {
			return err
		}
		return nil
	}

	if !nameInfo.ready {
		return nil
	}

	newTLSSecret, err := c.createNewTLSSecret(ctx, ca, nameInfo.selectedIP, nameInfo.selectedHostname)
	if err != nil {
		return err
	}

	err = c.loadTLSCertFromSecret(newTLSSecret)
	if err != nil {
		return err
	}

	return nil
}

func (c *impersonatorConfigController) ensureCASecretIsCreated(ctx context.Context) (*certauthority.CA, error) {
	caSecret, err := c.secretsInformer.Lister().Secrets(c.namespace).Get(c.caSecretName)
	if err != nil && !k8serrors.IsNotFound(err) {
		return nil, err
	}

	var impersonationCA *certauthority.CA
	if k8serrors.IsNotFound(err) {
		impersonationCA, err = c.createCASecret(ctx)
	} else {
		crtBytes := caSecret.Data[caCrtKey]
		keyBytes := caSecret.Data[caKeyKey]
		impersonationCA, err = certauthority.Load(string(crtBytes), string(keyBytes))
	}
	if err != nil {
		return nil, err
	}

	return impersonationCA, nil
}

func (c *impersonatorConfigController) createCASecret(ctx context.Context) (*certauthority.CA, error) {
	impersonationCA, err := certauthority.New(pkix.Name{CommonName: caCommonName}, oneYear)
	if err != nil {
		return nil, fmt.Errorf("could not create impersonation CA: %w", err)
	}

	caPrivateKeyPEM, err := impersonationCA.PrivateKeyToPEM()
	if err != nil {
		return nil, err
	}

	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.caSecretName,
			Namespace: c.namespace,
			Labels:    c.labels,
		},
		Data: map[string][]byte{
			caCrtKey: impersonationCA.Bundle(),
			caKeyKey: caPrivateKeyPEM,
		},
		Type: v1.SecretTypeOpaque,
	}

	plog.Info("Creating CA certificates for impersonation proxy",
		"secret", c.caSecretName,
		"namespace", c.namespace)
	if _, err = c.k8sClient.CoreV1().Secrets(c.namespace).Create(ctx, &secret, metav1.CreateOptions{}); err != nil {
		return nil, err
	}

	return impersonationCA, nil
}

func (c *impersonatorConfigController) findDesiredTLSCertificateName(config *impersonator.Config) (*certNameInfo, error) {
	if config.HasEndpoint() {
		return c.findTLSCertificateNameFromEndpointConfig(config)
	}
	return c.findTLSCertificateNameFromLoadBalancer()
}

func (c *impersonatorConfigController) findTLSCertificateNameFromEndpointConfig(config *impersonator.Config) (*certNameInfo, error) {
	endpointMaybeWithPort := config.Endpoint
	endpointWithoutPort := strings.Split(endpointMaybeWithPort, ":")[0]
	parsedAsIP := net.ParseIP(endpointWithoutPort)
	if parsedAsIP != nil {
		return &certNameInfo{ready: true, selectedIP: parsedAsIP, clientEndpoint: endpointMaybeWithPort}, nil
	}
	return &certNameInfo{ready: true, selectedHostname: endpointWithoutPort, clientEndpoint: endpointMaybeWithPort}, nil
}

func (c *impersonatorConfigController) findTLSCertificateNameFromLoadBalancer() (*certNameInfo, error) {
	lb, err := c.servicesInformer.Lister().Services(c.namespace).Get(c.generatedLoadBalancerServiceName)
	notFound := k8serrors.IsNotFound(err)
	if notFound {
		// We aren't ready and will try again later in this case.
		return &certNameInfo{ready: false}, nil
	}
	if err != nil {
		return nil, err
	}
	ingresses := lb.Status.LoadBalancer.Ingress
	if len(ingresses) == 0 || (ingresses[0].Hostname == "" && ingresses[0].IP == "") {
		plog.Info("load balancer for impersonation proxy does not have an ingress yet, so skipping tls cert generation while we wait",
			"service", c.generatedLoadBalancerServiceName,
			"namespace", c.namespace)
		return &certNameInfo{ready: false}, nil
	}
	for _, ingress := range ingresses {
		hostname := ingress.Hostname
		if hostname != "" {
			return &certNameInfo{ready: true, selectedHostname: hostname, clientEndpoint: hostname}, nil
		}
	}
	for _, ingress := range ingresses {
		ip := ingress.IP
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			return &certNameInfo{ready: true, selectedIP: parsedIP, clientEndpoint: ip}, nil
		}
	}

	return nil, fmt.Errorf("could not find valid IP addresses or hostnames from load balancer %s/%s", c.namespace, lb.Name)
}

func (c *impersonatorConfigController) createNewTLSSecret(ctx context.Context, ca *certauthority.CA, ip net.IP, hostname string) (*v1.Secret, error) {
	var hostnames []string
	var ips []net.IP
	if hostname != "" {
		hostnames = []string{hostname}
	}
	if ip != nil {
		ips = []net.IP{ip}
	}

	impersonationCert, err := ca.Issue(pkix.Name{}, hostnames, ips, oneYear)
	if err != nil {
		return nil, fmt.Errorf("could not create impersonation cert: %w", err)
	}

	certPEM, keyPEM, err := certauthority.ToPEM(impersonationCert)
	if err != nil {
		return nil, err
	}

	newTLSSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.tlsSecretName,
			Namespace: c.namespace,
			Labels:    c.labels,
		},
		Data: map[string][]byte{
			v1.TLSPrivateKeyKey: keyPEM,
			v1.TLSCertKey:       certPEM,
		},
		Type: v1.SecretTypeTLS,
	}

	plog.Info("Creating TLS certificates for impersonation proxy",
		"ips", ips,
		"hostnames", hostnames,
		"secret", c.tlsSecretName,
		"namespace", c.namespace)
	return c.k8sClient.CoreV1().Secrets(c.namespace).Create(ctx, newTLSSecret, metav1.CreateOptions{})
}

func (c *impersonatorConfigController) loadTLSCertFromSecret(tlsSecret *v1.Secret) error {
	certPEM := tlsSecret.Data[v1.TLSCertKey]
	keyPEM := tlsSecret.Data[v1.TLSPrivateKeyKey]
	_, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		c.tlsServingCertDynamicCertProvider.Set(nil, nil)
		return fmt.Errorf("could not parse TLS cert PEM data from Secret: %w", err)
	}
	plog.Info("Loading TLS certificates for impersonation proxy",
		"certPEM", string(certPEM),
		"secret", c.tlsSecretName,
		"namespace", c.namespace)
	c.tlsServingCertDynamicCertProvider.Set(certPEM, keyPEM)
	return nil
}

func (c *impersonatorConfigController) ensureTLSSecretIsRemoved(ctx context.Context) error {
	tlsSecretExists, _, err := c.tlsSecretExists()
	if err != nil {
		return err
	}
	if !tlsSecretExists {
		return nil
	}
	plog.Info("Deleting TLS certificates for impersonation proxy",
		"secret", c.tlsSecretName,
		"namespace", c.namespace)
	err = c.k8sClient.CoreV1().Secrets(c.namespace).Delete(ctx, c.tlsSecretName, metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	c.tlsServingCertDynamicCertProvider.Set(nil, nil)

	return nil
}

func (c *impersonatorConfigController) loadSignerCA(status v1alpha1.StrategyStatus) error {
	// Clear it when the impersonator is not completely ready.
	if status != v1alpha1.SuccessStrategyStatus {
		c.clearSignerCA()
		return nil
	}

	signingCertSecret, err := c.secretsInformer.Lister().Secrets(c.namespace).Get(c.impersonationSignerSecretName)
	if err != nil {
		return fmt.Errorf("could not load the impersonator's credential signing secret: %w", err)
	}

	certPEM := signingCertSecret.Data[apicerts.CACertificateSecretKey]
	keyPEM := signingCertSecret.Data[apicerts.CACertificatePrivateKeySecretKey]
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("could not load the impersonator's credential signing secret: %w", err)
	}

	plog.Info("Loading credential signing certificate for impersonation proxy",
		"certPEM", string(certPEM),
		"fromSecret", c.impersonationSignerSecretName,
		"namespace", c.namespace)
	c.impersonationSigningCertProvider.Set(certPEM, keyPEM)
	return nil
}

func (c *impersonatorConfigController) clearSignerCA() {
	plog.Info("Clearing credential signing certificate for impersonation proxy")
	c.impersonationSigningCertProvider.Set(nil, nil)
}

func (c *impersonatorConfigController) doSyncResult(nameInfo *certNameInfo, config *impersonator.Config, ca *certauthority.CA) *v1alpha1.CredentialIssuerStrategy {
	switch {
	case c.disabledExplicitly(config):
		return &v1alpha1.CredentialIssuerStrategy{
			Type:           v1alpha1.ImpersonationProxyStrategyType,
			Status:         v1alpha1.ErrorStrategyStatus,
			Reason:         v1alpha1.DisabledStrategyReason,
			Message:        "impersonation proxy was explicitly disabled by configuration",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
		}
	case c.disabledByAutoMode(config):
		return &v1alpha1.CredentialIssuerStrategy{
			Type:           v1alpha1.ImpersonationProxyStrategyType,
			Status:         v1alpha1.ErrorStrategyStatus,
			Reason:         v1alpha1.DisabledStrategyReason,
			Message:        "automatically determined that impersonation proxy should be disabled",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
		}
	case !nameInfo.ready:
		return &v1alpha1.CredentialIssuerStrategy{
			Type:           v1alpha1.ImpersonationProxyStrategyType,
			Status:         v1alpha1.ErrorStrategyStatus,
			Reason:         v1alpha1.PendingStrategyReason,
			Message:        "waiting for load balancer Service to be assigned IP or hostname",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
		}
	default:
		return &v1alpha1.CredentialIssuerStrategy{
			Type:           v1alpha1.ImpersonationProxyStrategyType,
			Status:         v1alpha1.SuccessStrategyStatus,
			Reason:         v1alpha1.ListeningStrategyReason,
			Message:        "impersonation proxy is ready to accept client connections",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
			Frontend: &v1alpha1.CredentialIssuerFrontend{
				Type: v1alpha1.ImpersonationProxyFrontendType,
				ImpersonationProxyInfo: &v1alpha1.ImpersonationProxyInfo{
					Endpoint:                 "https://" + nameInfo.clientEndpoint,
					CertificateAuthorityData: base64.StdEncoding.EncodeToString(ca.Bundle()),
				},
			},
		}
	}
}
