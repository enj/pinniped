package kubeclient

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"

	pinnipedclientset "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned"
	authenticationv1alpha1 "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/typed/authentication/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/typed/config/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/typed/login/v1alpha1"
)

func New(ref metav1.OwnerReference) (
	corev1.CoreV1Interface,
	apiregistrationv1.ApiregistrationV1Interface,
	authenticationv1alpha1.AuthenticationV1alpha1Interface,
	configv1alpha1.ConfigV1alpha1Interface,
	loginv1alpha1.LoginV1alpha1Interface,
	error,
) {
	// assume we are always running in a pod with the service account token mounted
	kubeConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
	}

	// explicitly use protobuf when talking to built-in kube APIs
	protoKubeConfig := createProtoKubeConfig(kubeConfig)

	// Connect to the core Kubernetes API.
	k8sClient, err := kubernetes.NewForConfig(protoKubeConfig)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("could not initialize Kubernetes client: %w", err)
	}

	// Connect to the Kubernetes aggregation API.
	aggregatorClient, err := aggregatorclient.NewForConfig(protoKubeConfig)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("could not initialize aggregation client: %w", err)
	}

	// Connect to the pinniped API.
	// We cannot use protobuf encoding here because we are using CRDs
	// (for which protobuf encoding is not yet supported).
	pinnipedClient, err := pinnipedclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("could not initialize pinniped client: %w", err)
	}

	// get all the REST clients we want to mutate
	core := k8sClient.CoreV1()
	apiregistration := aggregatorClient.ApiregistrationV1()
	auth := pinnipedClient.AuthenticationV1alpha1()
	config := pinnipedClient.ConfigV1alpha1()
	login := pinnipedClient.LoginV1alpha1()

	// mutate the REST clients and override their encoders slightly
	injectOwnerRef(ref, core, apiregistration, auth, config, login)

	// TODO write the wrapper client sets and make mega client
	return core, apiregistration, auth, config, login, nil
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
