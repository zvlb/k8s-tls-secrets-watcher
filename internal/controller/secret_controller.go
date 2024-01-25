/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/zvlb/k8s-tls-secrets-watcher/internal/cache"
	api_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"
)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Cache cache.Cache

	log logr.Logger
}

//+kubebuilder:rbac:resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:resources=secrets/status,verbs=get;update;patch
//+kubebuilder:rbac:resources=secrets/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.15.0/pkg/reconcile
func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.log = log.FromContext(ctx).WithValues("Kubernetes TLS Secret", req.NamespacedName)

	// Get the secret
	secret := &corev1.Secret{}
	err := r.Get(ctx, req.NamespacedName, secret)
	if err != nil {
		if api_errors.IsNotFound(err) {
			r.log.Info("Secret not found. Delete from cache")
			r.Cache.Delete(req.Name, req.Namespace)
		}
		return ctrl.Result{}, err
	}

	// if req.Name != "zhdun-space" {
	// 	return ctrl.Result{}, nil
	// }

	if !isTLSSecret(secret) {
		return ctrl.Result{}, nil
	}

	r.log.Info("Secret found. Add or upgrade in cache")
	r.Cache.AddOrUpgrade(secret.Name, secret.Namespace, secret.Data["tls.crt"], secret.Data["tls.key"])

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(r)
}

func isTLSSecret(secret *corev1.Secret) bool {
	return secret.Type == corev1.SecretTypeTLS
}
