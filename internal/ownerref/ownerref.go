// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ownerref

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/kubeclient"
)

// TODO this code assumes all objects are in the same namespace.
//  i.e. it assumes all objects are safe to set an owner ref on
//  i.e. the owner could be in a different namespace than the child which is invalid
//  i.e. the owner could be namespace scoped and thus cannot own a cluster scoped object
//  We guard against the last issue by ignoring objects that are cluster scoped
//  We could always use an owner ref to a cluster scoped object to get around all of these issues

func New(ref metav1.OwnerReference) kubeclient.Middleware {
	return kubeclient.MiddlewareFunc(func(_ context.Context, rt kubeclient.RoundTrip) {
		// we should not mess with owner refs on things we did not create
		if rt.Verb() != kubeclient.VerbCreate {
			return
		}

		// do not set ref on cluster scoped objects
		// note that this does not guard against owners and children being in different namespaces
		if rt.Namespace() == metav1.NamespaceNone {
			return
		}

		rt.MutateRequest(func(obj kubeclient.Object) {
			// we only want to set the owner ref on create and when one is not already present
			if len(obj.GetOwnerReferences()) != 0 {
				return
			}

			obj.SetOwnerReferences([]metav1.OwnerReference{ref})
		})
	})
}
