// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeIdentityV1alpha1 struct {
	*testing.Fake
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeIdentityV1alpha1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
