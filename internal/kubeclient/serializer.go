package kubeclient

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type passthroughDecoder struct{}

func (d passthroughDecoder) Decode(data []byte, _ *schema.GroupVersionKind, _ runtime.Object) (runtime.Object, *schema.GroupVersionKind, error) {
	return &runtime.Unknown{Raw: data}, &schema.GroupVersionKind{}, nil
}
