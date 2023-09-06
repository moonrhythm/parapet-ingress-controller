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
		--opt build-arg:VERSION=$(COMMIT_SHA)-hack \
		--opt build-arg:GOAMD64=v3 \
		--opt build-arg:BUILD_TAGS=cbrotli \
		--output type=image,name=gcr.io/moonrhythm-containers/parapet-ingress-controller:$(COMMIT_SHA)-hack,push=true
