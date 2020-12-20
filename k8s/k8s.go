package k8s

import (
	"context"
	"os"

	v1 "k8s.io/api/core/v1"
	"k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var client *kubernetes.Clientset

// Init inits k8s client
func Init() error {
	var (
		config *rest.Config
		err    error
	)

	if os.Getenv("KUBERNETES_LOCAL") == "true" {
		config = &rest.Config{
			Host: "127.0.0.1:8001",
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return err
		}
	}

	client, err = kubernetes.NewForConfig(config)
	return err
}

// WatchIngresses watches ingresses for given namespace
func WatchIngresses(ctx context.Context, namespace string) (watch.Interface, error) {
	return client.NetworkingV1beta1().Ingresses(namespace).Watch(ctx, metav1.ListOptions{})
}

// GetServices lists all service
func GetServices(ctx context.Context, namespace string) ([]v1.Service, error) {
	list, err := client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// WatchServices watches services
func WatchServices(ctx context.Context, namespace string) (watch.Interface, error) {
	return client.CoreV1().Services(namespace).Watch(ctx, metav1.ListOptions{})
}

// GetIngresses lists all ingresses for given namespace
func GetIngresses(ctx context.Context, namespace string) ([]v1beta1.Ingress, error) {
	list, err := client.NetworkingV1beta1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// GetSecrets lists all secret for given namespace
func GetSecrets(ctx context.Context, namespace string) ([]v1.Secret, error) {
	list, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// WatchSecrets watches secrets for given namespace
func WatchSecrets(ctx context.Context, namespace string) (watch.Interface, error) {
	return client.CoreV1().Secrets(namespace).Watch(ctx, metav1.ListOptions{})
}

// GetEndpoints lists all endpoints
func GetEndpoints(ctx context.Context, namespace string) ([]v1.Endpoints, error) {
	list, err := client.CoreV1().Endpoints(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// WatchEndpoints watches endpoints
func WatchEndpoints(ctx context.Context, namespace string) (watch.Interface, error) {
	return client.CoreV1().Endpoints(namespace).Watch(ctx, metav1.ListOptions{})
}
