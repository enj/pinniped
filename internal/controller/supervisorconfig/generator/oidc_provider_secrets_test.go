// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/supervisor/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func TestOIDCProviderControllerFilterSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		secret     corev1.Secret
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
		wantParent controllerlib.Key
	}{
		{
			name: "no owner reference",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{},
			},
		},
		{
			name: "owner reference without correct APIVersion",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:       "OIDCProvider",
							Name:       "some-name",
							Controller: boolPtr(true),
						},
					},
				},
			},
		},
		{
			name: "owner reference without correct Kind",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: configv1alpha1.SchemeGroupVersion.String(),
							Name:       "some-name",
							Controller: boolPtr(true),
						},
					},
				},
			},
		},
		{
			name: "owner reference without controller set to true",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: configv1alpha1.SchemeGroupVersion.String(),
							Kind:       "OIDCProvider",
							Name:       "some-name",
						},
					},
				},
			},
		},
		{
			name: "correct owner reference",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: configv1alpha1.SchemeGroupVersion.String(),
							Kind:       "OIDCProvider",
							Name:       "some-name",
							Controller: boolPtr(true),
						},
					},
				},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
			wantParent: controllerlib.Key{Namespace: "some-namespace", Name: "some-name"},
		},
		{
			name: "multiple owner references",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: "UnrelatedKind",
						},
						{
							APIVersion: configv1alpha1.SchemeGroupVersion.String(),
							Kind:       "OIDCProvider",
							Name:       "some-name",
							Controller: boolPtr(true),
						},
					},
				},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
			wantParent: controllerlib.Key{Namespace: "some-namespace", Name: "some-name"},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			secretInformer := kubeinformers.NewSharedInformerFactory(
				kubernetesfake.NewSimpleClientset(),
				0,
			).Core().V1().Secrets()
			opcInformer := pinnipedinformers.NewSharedInformerFactory(
				pinnipedfake.NewSimpleClientset(),
				0,
			).Config().V1alpha1().OIDCProviders()
			withInformer := testutil.NewObservableWithInformerOption()
			_ = NewOIDCProviderSecretsController(
				secretNameFunc,
				nil, // labels, not needed
				fakeSecretDataFunc,
				nil, // kubeClient, not needed
				nil, // pinnipedClient, not needed
				secretInformer,
				opcInformer,
				withInformer.WithInformer,
			)

			unrelated := corev1.Secret{}
			filter := withInformer.GetFilterForInformer(secretInformer)
			require.Equal(t, test.wantAdd, filter.Add(&test.secret))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelated, &test.secret))
			require.Equal(t, test.wantUpdate, filter.Update(&test.secret, &unrelated))
			require.Equal(t, test.wantDelete, filter.Delete(&test.secret))
			require.Equal(t, test.wantParent, filter.Parent(&test.secret))
		})
	}
}

func TestNewOIDCProviderSecretsControllerFilterOPC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		opc        configv1alpha1.OIDCProvider
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
		wantParent controllerlib.Key
	}{
		{
			name:       "anything goes",
			opc:        configv1alpha1.OIDCProvider{},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
			wantParent: controllerlib.Key{},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			secretInformer := kubeinformers.NewSharedInformerFactory(
				kubernetesfake.NewSimpleClientset(),
				0,
			).Core().V1().Secrets()
			opcInformer := pinnipedinformers.NewSharedInformerFactory(
				pinnipedfake.NewSimpleClientset(),
				0,
			).Config().V1alpha1().OIDCProviders()
			withInformer := testutil.NewObservableWithInformerOption()
			_ = NewOIDCProviderSecretsController(
				secretNameFunc,
				nil, // labels, not needed
				fakeSecretDataFunc,
				nil, // kubeClient, not needed
				nil, // pinnipedClient, not needed
				secretInformer,
				opcInformer,
				withInformer.WithInformer,
			)

			unrelated := configv1alpha1.OIDCProvider{}
			filter := withInformer.GetFilterForInformer(opcInformer)
			require.Equal(t, test.wantAdd, filter.Add(&test.opc))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelated, &test.opc))
			require.Equal(t, test.wantUpdate, filter.Update(&test.opc, &unrelated))
			require.Equal(t, test.wantDelete, filter.Delete(&test.opc))
			require.Equal(t, test.wantParent, filter.Parent(&test.opc))
		})
	}
}

func TestNewOIDCProviderSecretsControllerSync(t *testing.T) {
	// We shouldn't run this test in parallel since it messes with a global function (generateKey).

	const namespace = "tuna-namespace"

	opcGVR := schema.GroupVersionResource{
		Group:    configv1alpha1.SchemeGroupVersion.Group,
		Version:  configv1alpha1.SchemeGroupVersion.Version,
		Resource: "oidcproviders",
	}

	goodOPC := &configv1alpha1.OIDCProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "good-opc",
			Namespace: namespace,
			UID:       "good-opc-uid",
		},
		Spec: configv1alpha1.OIDCProviderSpec{
			Issuer: "https://some-issuer.com",
		},
	}

	expectedSecretName := secretNameFunc(goodOPC)

	secretGVR := schema.GroupVersionResource{
		Group:    corev1.SchemeGroupVersion.Group,
		Version:  corev1.SchemeGroupVersion.Version,
		Resource: "secrets",
	}

	newSecret := func(secretData map[string][]byte) *corev1.Secret {
		s := corev1.Secret{
			Type: symmetricKeySecretType,
			ObjectMeta: metav1.ObjectMeta{
				Name:      expectedSecretName,
				Namespace: namespace,
				Labels: map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         opcGVR.GroupVersion().String(),
						Kind:               "OIDCProvider",
						Name:               goodOPC.Name,
						UID:                goodOPC.UID,
						BlockOwnerDeletion: boolPtr(true),
						Controller:         boolPtr(true),
					},
				},
			},
			Data: secretData,
		}

		return &s
	}

	secretData, err := fakeSecretDataFunc()
	require.NoError(t, err)

	goodSecret := newSecret(secretData)

	tests := []struct {
		name                 string
		key                  controllerlib.Key
		secrets              []*corev1.Secret
		configKubeClient     func(*kubernetesfake.Clientset)
		configPinnipedClient func(*pinnipedfake.Clientset)
		opcs                 []*configv1alpha1.OIDCProvider
		generateKeyErr       error
		wantGenerateKeyCount int
		wantSecretActions    []kubetesting.Action
		wantOPCActions       []kubetesting.Action
		wantError            string
	}{
		{
			name: "new opc with no secret",
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewCreateAction(secretGVR, namespace, goodSecret),
			},
			wantOPCActions: []kubetesting.Action{
				kubetesting.NewGetAction(opcGVR, namespace, goodOPC.Name),
			},
		},
		{
			name: "opc without status with existing secret",
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			secrets: []*corev1.Secret{
				goodSecret,
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
			},
			wantOPCActions: []kubetesting.Action{
				kubetesting.NewGetAction(opcGVR, namespace, goodOPC.Name),
			},
		},
		{
			name: "existing opc with no secret",
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewCreateAction(secretGVR, namespace, goodSecret),
			},
			wantOPCActions: []kubetesting.Action{
				kubetesting.NewGetAction(opcGVR, namespace, goodOPC.Name),
			},
		},
		{
			name: "existing opc with existing secret",
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			secrets: []*corev1.Secret{
				goodSecret,
			},
		},
		{
			name: "deleted opc",
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			// Nothing to do here since Kube will garbage collect our child secret via its OwnerReference.
		},
		{
			name: "secret data is empty",
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			secrets: []*corev1.Secret{
				newSecret(map[string][]byte{}),
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantOPCActions: []kubetesting.Action{
				kubetesting.NewGetAction(opcGVR, namespace, goodOPC.Name),
			},
		},
		{
			name: fmt.Sprintf("secret missing key %s", symmetricKeySecretDataKey),
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			secrets: []*corev1.Secret{
				newSecret(map[string][]byte{"badKey": []byte("some secret - must have at least 32 bytes")}),
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantOPCActions: []kubetesting.Action{
				kubetesting.NewGetAction(opcGVR, namespace, goodOPC.Name),
			},
		},
		{
			name: fmt.Sprintf("secret data value for key %s", symmetricKeySecretDataKey),
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			secrets: []*corev1.Secret{
				newSecret(map[string][]byte{symmetricKeySecretDataKey: {}}),
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantOPCActions: []kubetesting.Action{
				kubetesting.NewGetAction(opcGVR, namespace, goodOPC.Name),
			},
		},
		{
			name: "generate key fails",
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			generateKeyErr: errors.New("some generate error"),
			wantError:      "cannot generate secret: cannot generate key: some generate error",
		},
		{
			name: "get secret fails",
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			configKubeClient: func(client *kubernetesfake.Clientset) {
				client.PrependReactor("get", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some get error")
				})
			},
			wantError: "cannot create or update secret: cannot get secret: some get error",
		},
		{
			name: "create secret fails",
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			configKubeClient: func(client *kubernetesfake.Clientset) {
				client.PrependReactor("create", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some create error")
				})
			},
			wantError: "cannot create or update secret: cannot create secret: some create error",
		},
		{
			name: "update secret fails",
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			secrets: []*corev1.Secret{
				newSecret(map[string][]byte{}),
			},
			configKubeClient: func(client *kubernetesfake.Clientset) {
				client.PrependReactor("update", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some update error")
				})
			},
			wantError: "cannot create or update secret: some update error",
		},
		{
			name: "get opc fails",
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			configPinnipedClient: func(client *pinnipedfake.Clientset) {
				client.PrependReactor("get", "oidcproviders", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some get error")
				})
			},
			wantError: "cannot update opc: cannot get opc: some get error",
		},
		{
			name: "update opc fails",
			key:  controllerlib.Key{Namespace: goodOPC.Namespace, Name: goodOPC.Name},
			opcs: []*configv1alpha1.OIDCProvider{
				goodOPC,
			},
			configPinnipedClient: func(client *pinnipedfake.Clientset) {
				client.PrependReactor("update", "oidcproviders", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some update error")
				})
			},
			wantError: "cannot update opc: some update error",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// We shouldn't run this test in parallel since it messes with a global function (generateKey).
			generateKeyCount := 0
			generateKey := func() (map[string][]byte, error) {
				generateKeyCount++
				return map[string][]byte{
					symmetricKeySecretDataKey: []byte("some secret - must have at least 32 bytes"),
				}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			defer cancel()

			kubeAPIClient := kubernetesfake.NewSimpleClientset()
			kubeInformerClient := kubernetesfake.NewSimpleClientset()
			for _, secret := range test.secrets {
				require.NoError(t, kubeAPIClient.Tracker().Add(secret))
				require.NoError(t, kubeInformerClient.Tracker().Add(secret))
			}
			if test.configKubeClient != nil {
				test.configKubeClient(kubeAPIClient)
			}

			pinnipedAPIClient := pinnipedfake.NewSimpleClientset()
			pinnipedInformerClient := pinnipedfake.NewSimpleClientset()
			for _, opc := range test.opcs {
				require.NoError(t, pinnipedAPIClient.Tracker().Add(opc))
				require.NoError(t, pinnipedInformerClient.Tracker().Add(opc))
			}
			if test.configPinnipedClient != nil {
				test.configPinnipedClient(pinnipedAPIClient)
			}

			kubeInformers := kubeinformers.NewSharedInformerFactory(
				kubeInformerClient,
				0,
			)
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(
				pinnipedInformerClient,
				0,
			)

			c := NewOIDCProviderSecretsController(
				secretNameFunc,
				map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				generateKey,
				kubeAPIClient,
				pinnipedAPIClient,
				kubeInformers.Core().V1().Secrets(),
				pinnipedInformers.Config().V1alpha1().OIDCProviders(),
				controllerlib.WithInformer,
			)

			// Must start informers before calling TestRunSynchronously().
			kubeInformers.Start(ctx.Done())
			pinnipedInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, c)

			err := controllerlib.TestSync(t, c, controllerlib.Context{
				Context: ctx,
				Key:     test.key,
			})
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
				return
			}
			require.NoError(t, err)

			require.Equal(t, test.wantGenerateKeyCount, generateKeyCount)

			if test.wantSecretActions != nil {
				require.Equal(t, test.wantSecretActions, kubeAPIClient.Actions())
			}
			if test.wantOPCActions != nil {
				require.Equal(t, test.wantOPCActions, pinnipedAPIClient.Actions())
			}
		})
	}
}

func secretNameFunc(opc *configv1alpha1.OIDCProvider) string {
	return fmt.Sprintf("pinniped-%s-%s-test_secret", opc.Kind, opc.UID)
}

func fakeSecretDataFunc() (map[string][]byte, error) {
	return map[string][]byte{
		symmetricKeySecretDataKey: []byte("some secret - must have at least 32 bytes"),
	}, nil
}

func boolPtr(b bool) *bool { return &b }
