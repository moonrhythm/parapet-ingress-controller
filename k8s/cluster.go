package k8s

import (
	"context"

	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

type clusterClient struct {
	client *kubernetes.Clientset
}

func (c *clusterClient) WatchIngresses(ctx context.Context, namespace string) (watch.Interface, error) {
	return c.client.NetworkingV1beta1().Ingresses(namespace).Watch(ctx, metav1.ListOptions{})
}

func (c *clusterClient) GetServices(ctx context.Context, namespace string) ([]v1.Service, error) {
	list, err := c.client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (c *clusterClient) WatchServices(ctx context.Context, namespace string) (watch.Interface, error) {
	return c.client.CoreV1().Services(namespace).Watch(ctx, metav1.ListOptions{})
}

func (c *clusterClient) GetIngresses(ctx context.Context, namespace string) ([]networking.Ingress, error) {
	list, err := c.client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (c *clusterClient) GetSecrets(ctx context.Context, namespace string) ([]v1.Secret, error) {
	list, err := c.client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (c *clusterClient) WatchSecrets(ctx context.Context, namespace string) (watch.Interface, error) {
	return c.client.CoreV1().Secrets(namespace).Watch(ctx, metav1.ListOptions{})
}

func (c *clusterClient) GetEndpoints(ctx context.Context, namespace string) ([]v1.Endpoints, error) {
	list, err := c.client.CoreV1().Endpoints(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (c *clusterClient) WatchEndpoints(ctx context.Context, namespace string) (watch.Interface, error) {
	return c.client.CoreV1().Endpoints(namespace).Watch(ctx, metav1.ListOptions{})
}
