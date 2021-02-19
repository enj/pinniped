// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// WhoAmIRequestLister helps list WhoAmIRequests.
// All objects returned here must be treated as read-only.
type WhoAmIRequestLister interface {
	// List lists all WhoAmIRequests in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.WhoAmIRequest, err error)
	// Get retrieves the WhoAmIRequest from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.WhoAmIRequest, error)
	WhoAmIRequestListerExpansion
}

// whoAmIRequestLister implements the WhoAmIRequestLister interface.
type whoAmIRequestLister struct {
	indexer cache.Indexer
}

// NewWhoAmIRequestLister returns a new WhoAmIRequestLister.
func NewWhoAmIRequestLister(indexer cache.Indexer) WhoAmIRequestLister {
	return &whoAmIRequestLister{indexer: indexer}
}

// List lists all WhoAmIRequests in the indexer.
func (s *whoAmIRequestLister) List(selector labels.Selector) (ret []*v1alpha1.WhoAmIRequest, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.WhoAmIRequest))
	})
	return ret, err
}

// Get retrieves the WhoAmIRequest from the index for a given name.
func (s *whoAmIRequestLister) Get(name string) (*v1alpha1.WhoAmIRequest, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("whoamirequest"), name)
	}
	return obj.(*v1alpha1.WhoAmIRequest), nil
}
