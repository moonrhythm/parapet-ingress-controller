# Umbrella Makefile — delegates to the two implementations. Each implementation
# also has its own build tooling (go/Makefile, rust/Cargo).
.PHONY: test go-test rust-test go-build-dev

# Run both implementations' test suites.
test: go-test rust-test

go-test:
	cd go && go vet ./... && go test ./...

# Fast Rust core, then the full proxy+cluster surface.
rust-test:
	cd rust && cargo test -p parapet-ingress-controller
	cd rust && cargo test -p parapet-ingress-controller --features proxy,cluster

# Build the Go dev image (delegates to go/Makefile).
go-build-dev:
	$(MAKE) -C go build-dev
