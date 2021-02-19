// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	internalinterfaces "go.pinniped.dev/generated/1.19/client/concierge/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// WhoAmIRequests returns a WhoAmIRequestInformer.
	WhoAmIRequests() WhoAmIRequestInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// WhoAmIRequests returns a WhoAmIRequestInformer.
func (v *version) WhoAmIRequests() WhoAmIRequestInformer {
	return &whoAmIRequestInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}
