run-local:
	KUBERNETES_LOCAL=true \
 	HTTP_PORT=8080 \
 	HTTPS_PORT=8443 \
 	go run ./cmd/parapet-ingress-controller
