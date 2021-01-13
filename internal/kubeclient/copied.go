package kubeclient

import (
	"net/url"

	"k8s.io/apimachinery/pkg/runtime/schema"
	restclient "k8s.io/client-go/rest"
)

// copied from k8s.io/client-go/rest/url_utils.go

// defaultServerUrlFor is shared between IsConfigTransportTLS and RESTClientFor. It
// requires Host and Version to be set prior to being called.
func defaultServerUrlFor(config *restclient.Config) (*url.URL, string, error) {
	// TODO: move the default to secure when the apiserver supports TLS by default
	// config.Insecure is taken to mean "I want HTTPS but don't bother checking the certs against a CA."
	hasCA := len(config.CAFile) != 0 || len(config.CAData) != 0
	hasCert := len(config.CertFile) != 0 || len(config.CertData) != 0
	defaultTLS := hasCA || hasCert || config.Insecure
	host := config.Host
	if host == "" {
		host = "localhost"
	}

	if config.GroupVersion != nil {
		return restclient.DefaultServerURL(host, config.APIPath, *config.GroupVersion, defaultTLS)
	}
	return restclient.DefaultServerURL(host, config.APIPath, schema.GroupVersion{}, defaultTLS)
}
