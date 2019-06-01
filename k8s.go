package main

import (
	"github.com/golang/glog"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func newKubernetesClient() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

func getServicePort(namespace, serviceName, portName string) int {
	svc, err := client.CoreV1().Services(namespace).Get(serviceName, metav1.GetOptions{})
	if err != nil {
		glog.Error("can not get service %s/%s; %v\n", namespace, serviceName, err)
		return 0
	}

	for _, port := range svc.Spec.Ports {
		if port.Name == portName {
			return int(port.Port)
		}
	}
	return 0
}

func getIngresses() ([]v1beta1.Ingress, error) {
	list, err := client.ExtensionsV1beta1().Ingresses(namespace).List(metav1.ListOptions{})
	if err != nil {
		glog.Error("can not list ingresses;", err)
		return nil, err
	}
	return list.Items, nil
}

func getSecretTLS(namespace, name string) (cert []byte, key []byte, err error) {
	s, err := client.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	cert = s.Data["tls.crt"]
	key = s.Data["tls.key"]
	return
}
