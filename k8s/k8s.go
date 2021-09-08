package k8s

import (
	"context"
	"fmt"
	"os"

	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Init inits k8s client
func Init() error {
	switch os.Getenv("KUBERNETES_BACKEND") {
	default:
		config, err := rest.InClusterConfig()
		if err != nil {
			return err
		}

		k8sClient, err := kubernetes.NewForConfig(config)
		if err != nil {
			return err
		}

		client = &clusterClient{k8sClient}
	case "fs":
		kubeFS := os.Getenv("KUBERNETES_FS")
		if kubeFS == "" {
			return fmt.Errorf("KUBERNETES_FS required")
		}
		var err error
		client, err = newFSClient(kubeFS)
		return err
	case "local":
		k8sClient, err := kubernetes.NewForConfig(&rest.Config{
			Host: "127.0.0.1:8001",
		})
		if err != nil {
			return err
		}
		client = &clusterClient{k8sClient}
	}

	return nil
}

var client interface {
	WatchIngresses(ctx context.Context, namespace string) (watch.Interface, error)
	GetServices(ctx context.Context, namespace string) ([]v1.Service, error)
	WatchServices(ctx context.Context, namespace string) (watch.Interface, error)
	GetIngresses(ctx context.Context, namespace string) ([]networking.Ingress, error)
	GetSecrets(ctx context.Context, namespace string) ([]v1.Secret, error)
	WatchSecrets(ctx context.Context, namespace string) (watch.Interface, error)
	GetEndpoints(ctx context.Context, namespace string) ([]v1.Endpoints, error)
	WatchEndpoints(ctx context.Context, namespace string) (watch.Interface, error)
}

// WatchIngresses watches ingresses for given namespace
func WatchIngresses(ctx context.Context, namespace string) (watch.Interface, error) {
	return client.WatchIngresses(ctx, namespace)
}

// GetServices lists all service
func GetServices(ctx context.Context, namespace string) ([]v1.Service, error) {
	return client.GetServices(ctx, namespace)
}

// WatchServices watches services
func WatchServices(ctx context.Context, namespace string) (watch.Interface, error) {
	return client.WatchServices(ctx, namespace)
}

// GetIngresses lists all ingresses for given namespace
func GetIngresses(ctx context.Context, namespace string) ([]networking.Ingress, error) {
	return client.GetIngresses(ctx, namespace)
}

// GetSecrets lists all secret for given namespace
func GetSecrets(ctx context.Context, namespace string) ([]v1.Secret, error) {
	return client.GetSecrets(ctx, namespace)
}

// WatchSecrets watches secrets for given namespace
func WatchSecrets(ctx context.Context, namespace string) (watch.Interface, error) {
	return client.WatchSecrets(ctx, namespace)
}

// GetEndpoints lists all endpoints
func GetEndpoints(ctx context.Context, namespace string) ([]v1.Endpoints, error) {
	return client.GetEndpoints(ctx, namespace)
}

// WatchEndpoints watches endpoints
func WatchEndpoints(ctx context.Context, namespace string) (watch.Interface, error) {
	return client.WatchEndpoints(ctx, namespace)
}
