// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apicerts

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"go.pinniped.dev/internal/constable"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
)

type certsExpirerController struct {
	namespace               string
	certsSecretResourceName string
	k8sClient               kubernetes.Interface
	secretInformer          corev1informers.SecretInformer

	// renewBefore is the amount of time after the cert's issuance where
	// this controller will start to try to rotate it.
	renewBefore time.Duration

	secretKey string
}

// NewCertsExpirerController returns a controllerlib.Controller that will delete a
// certificate secret once it gets within some threshold of its expiration time. The
// deletion forces rotation of the secret with the help of other controllers.
func NewCertsExpirerController(
	namespace string,
	certsSecretResourceName string,
	k8sClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	renewBefore time.Duration,
	secretKey string,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "certs-expirer-controller",
			Syncer: &certsExpirerController{
				namespace:               namespace,
				certsSecretResourceName: certsSecretResourceName,
				k8sClient:               k8sClient,
				secretInformer:          secretInformer,
				renewBefore:             renewBefore,
				secretKey:               secretKey,
			},
		},
		withInformer(
			secretInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(certsSecretResourceName, namespace),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controller.Syncer.Sync.
func (c *certsExpirerController) Sync(ctx controllerlib.Context) error {
	secret, err := c.secretInformer.Lister().Secrets(c.namespace).Get(c.certsSecretResourceName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s/%s secret: %w", c.namespace, c.certsSecretResourceName, err)
	}
	if notFound {
		klog.Info("certsExpirerController Sync found that the secret does not exist yet or was deleted")
		return nil
	}

	notBefore, notAfter, err := c.getCertBounds(secret)
	if err != nil {
		return fmt.Errorf("failed to get cert bounds for secret %q with key %q: %w", secret.Name, c.secretKey, err)
	}

	certAge := time.Since(notBefore)
	renewDelta := certAge - c.renewBefore
	klog.Infof("certsExpirerController Sync found a renew delta of %s", renewDelta)
	if renewDelta >= 0 || time.Now().After(notAfter) {
		err := c.k8sClient.
			CoreV1().
			Secrets(c.namespace).
			Delete(ctx.Context, c.certsSecretResourceName, metav1.DeleteOptions{})
		if err != nil {
			// Do return an error here so that the controller library will reschedule
			// us to try deleting this cert again.
			return err
		}
	}

	return nil
}

// getCertBounds returns the NotBefore and NotAfter fields of the TLS
// certificate in the provided secret, or an error. Not that it expects the
// provided secret to contain the well-known data keys from this package (see
// certs_manager.go).
func (c *certsExpirerController) getCertBounds(secret *corev1.Secret) (time.Time, time.Time, error) {
	certPEM := secret.Data[c.secretKey]
	if certPEM == nil {
		return time.Time{}, time.Time{}, constable.Error("failed to find certificate")
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return time.Time{}, time.Time{}, constable.Error("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.NotBefore, cert.NotAfter, nil
}
