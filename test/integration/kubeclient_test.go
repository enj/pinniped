// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/ownerref"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/test/library"
)

func TestKubeClientOwnerRef(t *testing.T) {
	env := library.IntegrationEnv(t)

	ns := env.ConciergeNamespace

	c := library.NewClientset(t)

	s, err := c.CoreV1().Secrets(ns).Create(context.Background(),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-one-",
			},
			Data: map[string][]byte{"A": []byte("B")},
		}, metav1.CreateOptions{})
	require.NoError(t, err)

	ref := metav1.OwnerReference{
		APIVersion: "v1",
		Kind:       "Secret",
		Name:       s.Name,
		UID:        s.UID,
	}
	cc, err := kubeclient.New(ownerref.New(ref))
	require.NoError(t, err)

	s2, err := cc.Kubernetes.CoreV1().Secrets(ns).Create(context.Background(),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-two-",
			},
			Data: map[string][]byte{"A": []byte("B")},
		}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Error(library.Sdump(s2))
}
