// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/identity/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeWhoAmIRequests implements WhoAmIRequestInterface
type FakeWhoAmIRequests struct {
	Fake *FakeIdentityV1alpha1
}

var whoamirequestsResource = schema.GroupVersionResource{Group: "identity.concierge.pinniped.dev", Version: "v1alpha1", Resource: "whoamirequests"}

var whoamirequestsKind = schema.GroupVersionKind{Group: "identity.concierge.pinniped.dev", Version: "v1alpha1", Kind: "WhoAmIRequest"}

// Get takes name of the whoAmIRequest, and returns the corresponding whoAmIRequest object, and an error if there is any.
func (c *FakeWhoAmIRequests) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.WhoAmIRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(whoamirequestsResource, name), &v1alpha1.WhoAmIRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.WhoAmIRequest), err
}

// List takes label and field selectors, and returns the list of WhoAmIRequests that match those selectors.
func (c *FakeWhoAmIRequests) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.WhoAmIRequestList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(whoamirequestsResource, whoamirequestsKind, opts), &v1alpha1.WhoAmIRequestList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.WhoAmIRequestList{ListMeta: obj.(*v1alpha1.WhoAmIRequestList).ListMeta}
	for _, item := range obj.(*v1alpha1.WhoAmIRequestList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested whoAmIRequests.
func (c *FakeWhoAmIRequests) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(whoamirequestsResource, opts))
}

// Create takes the representation of a whoAmIRequest and creates it.  Returns the server's representation of the whoAmIRequest, and an error, if there is any.
func (c *FakeWhoAmIRequests) Create(ctx context.Context, whoAmIRequest *v1alpha1.WhoAmIRequest, opts v1.CreateOptions) (result *v1alpha1.WhoAmIRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(whoamirequestsResource, whoAmIRequest), &v1alpha1.WhoAmIRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.WhoAmIRequest), err
}

// Update takes the representation of a whoAmIRequest and updates it. Returns the server's representation of the whoAmIRequest, and an error, if there is any.
func (c *FakeWhoAmIRequests) Update(ctx context.Context, whoAmIRequest *v1alpha1.WhoAmIRequest, opts v1.UpdateOptions) (result *v1alpha1.WhoAmIRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(whoamirequestsResource, whoAmIRequest), &v1alpha1.WhoAmIRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.WhoAmIRequest), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeWhoAmIRequests) UpdateStatus(ctx context.Context, whoAmIRequest *v1alpha1.WhoAmIRequest, opts v1.UpdateOptions) (*v1alpha1.WhoAmIRequest, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(whoamirequestsResource, "status", whoAmIRequest), &v1alpha1.WhoAmIRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.WhoAmIRequest), err
}

// Delete takes name of the whoAmIRequest and deletes it. Returns an error if one occurs.
func (c *FakeWhoAmIRequests) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(whoamirequestsResource, name), &v1alpha1.WhoAmIRequest{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeWhoAmIRequests) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(whoamirequestsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.WhoAmIRequestList{})
	return err
}

// Patch applies the patch and returns the patched whoAmIRequest.
func (c *FakeWhoAmIRequests) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.WhoAmIRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(whoamirequestsResource, name, pt, data, subresources...), &v1alpha1.WhoAmIRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.WhoAmIRequest), err
}
