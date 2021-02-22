// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package whoamirequest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	identityapi "go.pinniped.dev/generated/latest/apis/concierge/identity"
)

func TestNew(t *testing.T) {
	r := NewREST(schema.GroupResource{Group: "bears", Resource: "panda"})
	require.NotNil(t, r)
	require.False(t, r.NamespaceScoped())
	require.Equal(t, []string{"pinniped"}, r.Categories())
	require.IsType(t, &identityapi.WhoAmIRequest{}, r.New())
	require.IsType(t, &identityapi.WhoAmIRequestList{}, r.NewList())

	ctx := context.Background()

	// check the simple invariants of our no-op list
	list, err := r.List(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, list)
	require.IsType(t, &identityapi.WhoAmIRequestList{}, list)
	require.Equal(t, "0", list.(*identityapi.WhoAmIRequestList).ResourceVersion)
	require.NotNil(t, list.(*identityapi.WhoAmIRequestList).Items)
	require.Len(t, list.(*identityapi.WhoAmIRequestList).Items, 0)

	// make sure we can turn lists into tables if needed
	table, err := r.ConvertToTable(ctx, list, nil)
	require.NoError(t, err)
	require.NotNil(t, table)
	require.Equal(t, "0", table.ResourceVersion)
	require.Nil(t, table.Rows)

	// exercise group resource - force error by passing a runtime.Object that does not have an embedded object meta
	_, err = r.ConvertToTable(ctx, &metav1.APIGroup{}, nil)
	require.Error(t, err, "the resource panda.bears does not support being converted to a Table")
}

func TestCreate(t *testing.T) {
	// TODO finish
}
