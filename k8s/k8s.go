package k8s

import (
	"github.com/golang/glog"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var client *kubernetes.Clientset

// Init inits k8s client
func Init() error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	client, err = kubernetes.NewForConfig(config)
	return err
}

// WatchIngresses watches ingresses for given namespace
func WatchIngresses(namespace string) (watch.Interface, error) {
	return client.ExtensionsV1beta1().Ingresses(namespace).Watch(metav1.ListOptions{})
}

// GetService gets service
func GetService(namespace, name string) (*v1.Service, error) {
	return client.CoreV1().Services(namespace).Get(name, metav1.GetOptions{})
	// if err != nil {
	// 	glog.Error("can not get service %s/%s; %v\n", namespace, serviceName, err)
	// 	return 0
	// }
	//
	// for _, port := range svc.Spec.Ports {
	// 	if port.Name == portName {
	// 		return int(port.Port)
	// 	}
	// }
	// return 0
}

// GetIngresses lists all ingresses for given namespace
func GetIngresses(namespace string) ([]v1beta1.Ingress, error) {
	list, err := client.ExtensionsV1beta1().Ingresses(namespace).List(metav1.ListOptions{})
	if err != nil {
		glog.Error("can not list ingresses;", err)
		return nil, err
	}
	return list.Items, nil
}

// GetSecretTLS gets tls from secret
func GetSecretTLS(namespace, name string) (cert []byte, key []byte, err error) {
	s, err := client.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	cert = s.Data["tls.crt"]
	key = s.Data["tls.key"]
	return
}
