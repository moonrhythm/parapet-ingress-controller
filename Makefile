# Makefile for parapet-ingress-controller (Go, at the repo root).
.PHONY: test go-test run-local go-build-dev

# Run the test suite.
test: go-test

go-test:
	go vet ./... && go test ./...

# Run the Go controller locally against the current kube context.
run-local:
	KUBERNETES_LOCAL=true \
	HTTP_PORT=8080 \
	HTTPS_PORT=8443 \
	go run ./cmd/parapet-ingress-controller

# Build the Go dev image.
go-build-dev:
	buildctl build \
        --frontend dockerfile.v0 \
        --local dockerfile=. \
        --local context=. \
        --output type=image,name=gcr.io/moonrhythm-containers/parapet-ingress-controller:dev,push=true
