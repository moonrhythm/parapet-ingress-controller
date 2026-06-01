# Umbrella Makefile. The Go implementation lives at the repo root; the Rust
# implementation lives in rust/ (build tooling: rust/Cargo).
.PHONY: test go-test rust-test run-local go-build-dev

# Run both implementations' test suites.
test: go-test rust-test

go-test:
	go vet ./... && go test ./...

# Fast Rust core, then the full proxy+cluster surface.
rust-test:
	cd rust && cargo test -p parapet-ingress-controller
	cd rust && cargo test -p parapet-ingress-controller --features proxy,cluster

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
