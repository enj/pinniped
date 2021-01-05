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

func New(ref metav1.OwnerReference) (*Client, error) {
	// assume we are always running in a pod with the service account token mounted
	kubeConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
	}

	// explicitly use protobuf when talking to built-in kube APIs
	protoKubeConfig := createProtoKubeConfig(kubeConfig)

	// Connect to the core Kubernetes API.
	k8sClient, err := kubernetes.NewForConfig(configWithWrapper(protoKubeConfig, kubescheme.Codecs, ref))
	if err != nil {
		return nil, fmt.Errorf("could not initialize Kubernetes client: %w", err)
	}

	// Connect to the Kubernetes aggregation API.
	aggregatorClient, err := aggregatorclient.NewForConfig(configWithWrapper(protoKubeConfig, aggregatorclientscheme.Codecs, ref))
	if err != nil {
		return nil, fmt.Errorf("could not initialize aggregation client: %w", err)
	}

	// Connect to the pinniped API.
	// We cannot use protobuf encoding here because we are using CRDs
	// (for which protobuf encoding is not yet supported).
	pinnipedClient, err := pinnipedclientset.NewForConfig(configWithWrapper(kubeConfig, pinnipedclientsetscheme.Codecs, ref))
	if err != nil {
		return nil, fmt.Errorf("could not initialize pinniped client: %w", err)
	}

	return &Client{
		Kubernetes:  k8sClient,
		Aggregation: aggregatorClient,
		Pinniped:    pinnipedClient,
	}, nil
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
