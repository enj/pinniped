package kubeclient

import (
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var _ runtime.ClientNegotiator = &wrapperNegotiator{}

type wrapperNegotiator struct {
	delegate runtime.ClientNegotiator
	ref      metav1.OwnerReference
}

func (w *wrapperNegotiator) Encoder(contentType string, params map[string]string) (runtime.Encoder, error) {
	encoder, err := w.delegate.Encoder(contentType, params)
	if err != nil {
		return nil, fmt.Errorf("wrapperNegotiator: delegate.Encoder error: %w", err)
	}
	return &wrapperEncoder{delegate: encoder, ref: w.ref}, nil
}

func (w *wrapperNegotiator) Decoder(contentType string, params map[string]string) (runtime.Decoder, error) {
	return w.delegate.Decoder(contentType, params) // no-op passthrough
}

func (w *wrapperNegotiator) StreamDecoder(contentType string, params map[string]string) (runtime.Decoder, runtime.Serializer, runtime.Framer, error) {
	return w.delegate.StreamDecoder(contentType, params) // no-op passthrough
}

var _ runtime.Encoder = &wrapperEncoder{}

type wrapperEncoder struct {
	delegate runtime.Encoder
	ref      metav1.OwnerReference
}

func (w *wrapperEncoder) Encode(obj runtime.Object, writer io.Writer) error {
	if needsOwnerRef(obj) {
		obj = obj.DeepCopyObject() // do not mutate input as it could be from an informer
		setOwnerRef(obj, w.ref)
	}
	return w.delegate.Encode(obj, writer)
}

func (w *wrapperEncoder) Identifier() runtime.Identifier {
	return "pinniped-owner-ref-encoder-" + w.delegate.Identifier() // I do not think this actually matters but just to be safe
}

// TODO this func assumes all objects are namespace scoped and are in the same namespace
//  i.e. it assumes all objects are safe to set an owner ref on
//  i.e. the owner could be namespace scoped and thus cannot own a cluster scoped object
//  this could be fixed by using a rest mapper to confirm the REST scoping
//  or we could always use an owner ref to a cluster scoped object
func needsOwnerRef(obj runtime.Object) bool {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return false
	}
	// ignore objects that already have a creation timestamp, i.e. on update
	// we only want to set the owner ref on create and when one is not already present
	return accessor.GetCreationTimestamp().IsZero() && len(accessor.GetOwnerReferences()) == 0
}

func setOwnerRef(obj runtime.Object, ref metav1.OwnerReference) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		panic(err) // assumes we checked this already to see if we need to set the ref at all
	}
	accessor.SetOwnerReferences([]metav1.OwnerReference{ref})
}
