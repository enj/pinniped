// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apicerts

import (
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/klog/v2"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/dynamiccert"
)

type certsObserverController struct {
	namespace               string
	certsSecretResourceName string
	dynamicCertProvider     dynamiccert.Provider
	secretInformer          corev1informers.SecretInformer
}

func NewCertsObserverController(
	namespace string,
	certsSecretResourceName string,
	dynamicCertProvider dynamiccert.Provider,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "certs-observer-controller",
			Syncer: &certsObserverController{
				namespace:               namespace,
				certsSecretResourceName: certsSecretResourceName,
				dynamicCertProvider:     dynamicCertProvider,
				secretInformer:          secretInformer,
			},
		},
		withInformer(
			secretInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(certsSecretResourceName, namespace),
			controllerlib.InformerOption{},
		),
	)
}

func (c *certsObserverController) Sync(_ controllerlib.Context) error {
	// Try to get the secret from the informer cache.
	certSecret, err := c.secretInformer.Lister().Secrets(c.namespace).Get(c.certsSecretResourceName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s/%s secret: %w", c.namespace, c.certsSecretResourceName, err)
	}
	if notFound {
		klog.Info("certsObserverController Sync found that the secret does not exist yet or was deleted")
		// The secret does not exist yet or was deleted.
		c.dynamicCertProvider.Set(nil, nil)
		return nil
	}

	// Mutate the in-memory cert provider to update with the latest cert values.
	c.dynamicCertProvider.Set(certSecret.Data[TLSCertificateChainSecretKey], certSecret.Data[tlsPrivateKeySecretKey])
	klog.Info("certsObserverController Sync updated certs in the dynamic cert provider")
	return nil
}
