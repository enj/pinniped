package kubeclient

import (
	"reflect"
	"unsafe"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	restclient "k8s.io/client-go/rest"
)

type restClientGetter interface {
	RESTClient() restclient.Interface
}

func injectOwnerRef(ref metav1.OwnerReference, getters ...restClientGetter) {
	for _, getter := range getters {
		getter := getter
		setClientContentConfig(getter.RESTClient().(*restclient.RESTClient), // hack 1
			func(config *restclient.ClientContentConfig) {
				config.Negotiator = &wrapperNegotiator{
					delegate: config.Negotiator,
					ref:      ref,
				}
			})
	}
}

func setClientContentConfig(rc *restclient.RESTClient, setter func(*restclient.ClientContentConfig)) {
	contentField := reflect.ValueOf(rc).Elem().FieldByName("content")                              // hack 2
	contentPointer := (*restclient.ClientContentConfig)(unsafe.Pointer(contentField.UnsafeAddr())) // hack 3
	setter(contentPointer)
}
