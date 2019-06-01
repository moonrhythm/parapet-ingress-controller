package main

import (
	"github.com/golang/glog"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getServicePort(serviceName, portName string) int {
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
