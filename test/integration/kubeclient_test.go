// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/ownerref"
	"go.pinniped.dev/test/library"
)

func TestKubeClientOwnerRef(t *testing.T) {
	env := library.IntegrationEnv(t)

	regularClient := library.NewClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	namespaces := regularClient.CoreV1().Namespaces()

	namespace, err := namespaces.Create(
		ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "test-owner-ref-"}},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)

	defer func() {
		if t.Failed() {
			return
		}
		err := namespaces.Delete(ctx, namespace.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	}()

	// create something that we can point to
	parentSecret, err := regularClient.CoreV1().Secrets(namespace.Name).Create(
		ctx,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName:    "parent-",
				OwnerReferences: nil, // no owner refs set
			},
			Data: map[string][]byte{"A": []byte("B")},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)
	require.Len(t, parentSecret.OwnerReferences, 0)

	// create a client that should set an owner ref back to parent on create
	ref := metav1.OwnerReference{
		APIVersion: "v1",
		Kind:       "Secret",
		Name:       parentSecret.Name,
		UID:        parentSecret.UID,
	}
	ownerRefClient, err := kubeclient.New(
		kubeclient.WithMiddleware(ownerref.New(ref)),
		kubeclient.WithConfig(library.NewClientConfig(t)),
	)
	require.NoError(t, err)

	ownerRefSecrets := ownerRefClient.Kubernetes.CoreV1().Secrets(namespace.Name)

	// we expect this secret to have the owner ref set even though we did not set it explicitly
	childSecret, err := ownerRefSecrets.Create(
		ctx,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName:    "child-",
				OwnerReferences: nil, // no owner refs set
			},
			Data: map[string][]byte{"C": []byte("D")},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)
	require.Len(t, childSecret.OwnerReferences, 1)
	require.Equal(t, ref, childSecret.OwnerReferences[0])

	preexistingRef := *ref.DeepCopy()
	preexistingRef.Name = "different"
	preexistingRef.UID = "different"

	// we expect this secret to keep the owner ref that is was created with
	otherSecret, err := ownerRefSecrets.Create(
		ctx,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName:    "child-",
				OwnerReferences: []metav1.OwnerReference{preexistingRef}, // owner ref set explicitly
			},
			Data: map[string][]byte{"C": []byte("D")},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)
	require.Len(t, otherSecret.OwnerReferences, 1)
	require.Equal(t, preexistingRef, otherSecret.OwnerReferences[0])
	require.NotEqual(t, ref, preexistingRef)

	// we expect no owner ref to be set on update
	parentSecretUpdate := parentSecret.DeepCopy()
	parentSecretUpdate.Data = map[string][]byte{"E": []byte("F ")}
	updatedParentSecret, err := ownerRefSecrets.Update(ctx, parentSecretUpdate, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Equal(t, parentSecret.UID, updatedParentSecret.UID)
	require.NotEqual(t, parentSecret.ResourceVersion, updatedParentSecret.ResourceVersion)
	require.Len(t, updatedParentSecret.OwnerReferences, 0)

	// delete the parent object
	err = ownerRefSecrets.Delete(ctx, parentSecret.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	// the child object should be cleaned up on its own
	require.Eventually(t, func() bool {
		_, err := ownerRefSecrets.Get(ctx, childSecret.Name, metav1.GetOptions{})
		switch {
		case err == nil:
			return false
		case errors.IsNotFound(err):
			return true
		default:
			require.NoError(t, err)
			return false
		}
	}, time.Minute, time.Second)

	// TODO use aggregation and pinniped client x2

	// check some well-known, always created secrets to make sure they have an owner ref back to their deployment

	dref := metav1.OwnerReference{}
	dref.APIVersion, dref.Kind = appsv1.SchemeGroupVersion.WithKind("Deployment").ToAPIVersionAndKind()

	supervisorDeployment, err := ownerRefClient.Kubernetes.AppsV1().Deployments(env.SupervisorNamespace).Get(ctx, env.SupervisorAppName, metav1.GetOptions{})
	require.NoError(t, err)

	supervisorKey, err := ownerRefClient.Kubernetes.CoreV1().Secrets(env.SupervisorNamespace).Get(ctx, env.SupervisorAppName+"-key", metav1.GetOptions{})
	require.NoError(t, err)

	supervisorDref := *dref.DeepCopy()
	supervisorDref.Name = env.SupervisorAppName
	supervisorDref.UID = supervisorDeployment.UID
	require.Len(t, supervisorKey.OwnerReferences, 1)
	require.Equal(t, supervisorDref, supervisorKey.OwnerReferences[0])

	conciergeDeployment, err := ownerRefClient.Kubernetes.AppsV1().Deployments(env.ConciergeNamespace).Get(ctx, env.ConciergeAppName, metav1.GetOptions{})
	require.NoError(t, err)

	conciergeCert, err := ownerRefClient.Kubernetes.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, env.ConciergeAppName+"-api-tls-serving-certificate", metav1.GetOptions{})
	require.NoError(t, err)

	conciergeDref := *dref.DeepCopy()
	conciergeDref.Name = env.ConciergeAppName
	conciergeDref.UID = conciergeDeployment.UID
	require.Len(t, conciergeCert.OwnerReferences, 1)
	require.Equal(t, conciergeDref, conciergeCert.OwnerReferences[0])
}
