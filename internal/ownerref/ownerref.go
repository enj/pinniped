// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ownerref

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/kubeclient"
)

func New(ref metav1.OwnerReference, refNamespace string) kubeclient.Middleware {
	return kubeclient.MiddlewareFunc(func(_ context.Context, rt kubeclient.RoundTrip) {
		// we should not mess with owner refs on things we did not create
		if rt.Verb() != kubeclient.VerbCreate {
			return
		}

		// if the input refNamespace is empty, we assume the owner ref is to a cluster scoped object which can own any object
		// otherwise, we require refNamespace to match the request namespace since cross namespace ownership is disallowed
		if len(refNamespace) != 0 && refNamespace != rt.Namespace() {
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
