COMMIT_SHA=$(shell git rev-parse HEAD)

run-local:
	KUBERNETES_LOCAL=true \
 	HTTP_PORT=8080 \
 	HTTPS_PORT=8443 \
 	go run ./cmd/parapet-ingress-controller

build-dev:
	buildctl build \
        --frontend dockerfile.v0 \
        --local dockerfile=. \
        --local context=. \
        --output type=image,name=gcr.io/moonrhythm-containers/parapet-ingress-controller:dev,push=true

build-hack:
	buildctl build \
		--frontend dockerfile.v0 \
		--local dockerfile=. \
		--local context=. \
		--output type=image,name=gcr.io/moonrhythm-containers/parapet-ingress-controller:$(COMMIT_SHA)-hack,push=true
