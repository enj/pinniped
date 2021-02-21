// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	"go.pinniped.dev/test/library"
)

func TestWhoAmIKubeadm(t *testing.T) {
	// use the cluster signing key being available as a proxy for this being a kubeadm cluster
	_ = library.IntegrationEnv(t).WithCapability(library.ClusterSigningKeyIsAvailable)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	whoAmI, err := library.NewConciergeClientset(t).IdentityV1alpha1().WhoAmIRequests().
		Create(ctx, &v1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
	require.NoError(t, err)

	// this user info is based off of the bootstrap cert user created by kubeadm
	require.Equal(t,
		&v1alpha1.WhoAmIRequest{
			Status: v1alpha1.WhoAmIRequestStatus{
				KubernetesUserInfo: v1alpha1.KubernetesUserInfo{
					User: v1alpha1.UserInfo{
						Username: "kubernetes-admin",
						Groups: []string{
							"system:masters",
							"system:authenticated",
						},
					},
				},
			},
		},
		whoAmI,
	)
}

func TestWhoAmIServiceAccount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	kubeClient := library.NewKubernetesClientset(t).CoreV1()

	ns, err := kubeClient.Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-whoami-",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	defer func() {
		if t.Failed() {
			return
		}
		err := kubeClient.Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	}()

	sa, err := kubeClient.ServiceAccounts(ns.Name).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-whoami-",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	secret, err := kubeClient.Secrets(ns.Name).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-whoami-",
			Annotations: map[string]string{
				corev1.ServiceAccountNameKey: sa.Name,
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	library.RequireEventuallyWithoutError(t, func() (bool, error) {
		secret, err = kubeClient.Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return len(secret.Data[corev1.ServiceAccountTokenKey]) > 0, nil
	}, 30*time.Second, time.Second)

	saConfig := library.NewAnonymousClientRestConfig(t)
	saConfig.BearerToken = string(secret.Data[corev1.ServiceAccountTokenKey])

	whoAmI, err := library.NewKubeclient(t, saConfig).PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
		Create(ctx, &v1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
	require.NoError(t, err)

	// legacy service account tokens do not have any extra info
	require.Equal(t,
		&v1alpha1.WhoAmIRequest{
			Status: v1alpha1.WhoAmIRequestStatus{
				KubernetesUserInfo: v1alpha1.KubernetesUserInfo{
					User: v1alpha1.UserInfo{
						Username: "system:serviceaccount:" + ns.Name + ":" + sa.Name,
						Groups: []string{
							"system:serviceaccounts",
							"system:serviceaccounts:" + ns.Name,
							"system:authenticated",
						},
					},
				},
			},
		},
		whoAmI,
	)
}
