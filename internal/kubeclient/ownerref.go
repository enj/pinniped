package kubeclient

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

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
