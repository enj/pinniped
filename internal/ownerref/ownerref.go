// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ownerref

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/kubeclient"
)

// TODO this code assumes all objects are namespace scoped and are in the same namespace.
//  i.e. it assumes all objects are safe to set an owner ref on
//  i.e. the owner could be namespace scoped and thus cannot own a cluster scoped object
//  this could be fixed by using a rest mapper to confirm the REST scoping
//  or we could always use an owner ref to a cluster scoped object

func New(ref metav1.OwnerReference) kubeclient.Middleware {
	return kubeclient.MiddlewareFunc(func(_ context.Context, rt kubeclient.RoundTrip) {
		if rt.Verb() != kubeclient.VerbCreate {
			return
		}

		rt.Mutate(func(obj kubeclient.Object) {
			// we only want to set the owner ref on create and when one is not already present
			if len(obj.GetOwnerReferences()) != 0 {
				return
			}

			obj.SetOwnerReferences([]metav1.OwnerReference{ref})
		})
	})
}
