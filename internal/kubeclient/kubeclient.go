package kubeclient

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	aggregatorclientscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"

	pinnipedclientset "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned"
	pinnipedclientsetscheme "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/scheme"
)

type Client struct {
	Kubernetes  kubernetes.Interface
	Aggregation aggregatorclient.Interface
	Pinniped    pinnipedclientset.Interface
}

// TODO expand this interface to address more complex use cases
type Middleware interface {
	Handles(httpMethod string) bool
	Mutate(obj metav1.Object) (mutated bool)
}

func New(opts ...Option) (*Client, error) {
	c := &clientConfig{}

	for _, opt := range opts {
		opt(c)
	}

	// default to assuming we are running in a pod with the service account token mounted
	if c.config == nil {
		inClusterConfig, err := restclient.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
		}
		WithConfig(inClusterConfig)(c) // make sure all writes to clientConfig flow through one code path
	}

	// explicitly use json when talking to CRD APIs
	jsonKubeConfig := createJSONKubeConfig(c.config)

	// explicitly use protobuf when talking to built-in kube APIs
	protoKubeConfig := createProtoKubeConfig(c.config)

	// Connect to the core Kubernetes API.
	k8sClient, err := kubernetes.NewForConfig(configWithWrapper(protoKubeConfig, kubescheme.Codecs, c.middlewares))
	if err != nil {
		return nil, fmt.Errorf("could not initialize Kubernetes client: %w", err)
	}

	// Connect to the Kubernetes aggregation API.
	aggregatorClient, err := aggregatorclient.NewForConfig(configWithWrapper(protoKubeConfig, aggregatorclientscheme.Codecs, c.middlewares))
	if err != nil {
		return nil, fmt.Errorf("could not initialize aggregation client: %w", err)
	}

	// Connect to the pinniped API.
	// We cannot use protobuf encoding here because we are using CRDs
	// (for which protobuf encoding is not yet supported).
	pinnipedClient, err := pinnipedclientset.NewForConfig(configWithWrapper(jsonKubeConfig, pinnipedclientsetscheme.Codecs, c.middlewares))
	if err != nil {
		return nil, fmt.Errorf("could not initialize pinniped client: %w", err)
	}

	return &Client{
		Kubernetes:  k8sClient,
		Aggregation: aggregatorClient,
		Pinniped:    pinnipedClient,
	}, nil
}

// Returns a copy of the input config with the ContentConfig set to use json.
// Use this config to communicate with all CRD based APIs.
func createJSONKubeConfig(kubeConfig *restclient.Config) *restclient.Config {
	jsonKubeConfig := restclient.CopyConfig(kubeConfig)
	jsonKubeConfig.AcceptContentTypes = runtime.ContentTypeJSON
	jsonKubeConfig.ContentType = runtime.ContentTypeJSON
	return jsonKubeConfig
}

// Returns a copy of the input config with the ContentConfig set to use protobuf.
// Do not use this config to communicate with any CRD based APIs.
func createProtoKubeConfig(kubeConfig *restclient.Config) *restclient.Config {
	protoKubeConfig := restclient.CopyConfig(kubeConfig)
	const protoThenJSON = runtime.ContentTypeProtobuf + "," + runtime.ContentTypeJSON
	protoKubeConfig.AcceptContentTypes = protoThenJSON
	protoKubeConfig.ContentType = runtime.ContentTypeProtobuf
	return protoKubeConfig
}
