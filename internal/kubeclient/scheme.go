package kubeclient

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/gengo/namer"
	"k8s.io/gengo/types"
)

type objectList interface {
	runtime.Object       // generic access to TypeMeta
	metav1.ListInterface // generic access to ListMeta
}

func schemeRestMapper(scheme *runtime.Scheme) func(schema.GroupVersionResource, Verb) (schema.GroupVersionKind, bool) {
	// we are assuming that no code uses the `// +resourceName=CUSTOM_RESOURCE_NAME` directive
	pluralExceptions := map[string]string{"Endpoints": "Endpoints"} // copied from client-gen
	lowercaseNamer := namer.NewAllLowercasePluralNamer(pluralExceptions)

	listVerbMapping := map[schema.GroupVersionResource]schema.GroupVersionKind{}
	nonListVerbMapping := map[schema.GroupVersionResource]schema.GroupVersionKind{}

	for gvk := range scheme.AllKnownTypes() {
		obj, err := scheme.New(gvk)
		if err != nil {
			panic(err) // programmer error (internal scheme code is broken)
		}

		switch obj.(type) {
		case Object:
			resource := lowercaseNamer.Name(types.Ref("ignored", gvk.Kind))
			gvr := gvk.GroupVersion().WithResource(resource)
			nonListVerbMapping[gvr] = gvk

		case objectList:
			itemsPtr, err := meta.GetItemsPtr(obj)
			if err != nil {
				panic(err) // programmer error (internal scheme code is broken)
			}
			items, err := conversion.EnforcePtr(itemsPtr)
			if err != nil {
				panic(err) // programmer error (internal scheme code is broken)
			}
			nonListKind := items.Type().Elem().Name()
			resource := lowercaseNamer.Name(types.Ref("ignored", nonListKind))
			gvr := gvk.GroupVersion().WithResource(resource)
			listVerbMapping[gvr] = gvk

		default:
			// ignore stuff like ListOptions
		}
	}

	return func(resource schema.GroupVersionResource, v Verb) (schema.GroupVersionKind, bool) {
		switch v {
		case VerbList:
			gvk, ok := listVerbMapping[resource]
			return gvk, ok

		default:
			gvk, ok := nonListVerbMapping[resource]
			return gvk, ok
		}
	}
}
