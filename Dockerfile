FROM golang:1.21.3-bullseye

ARG VERSION
ARG GOAMD64

RUN apt-get update && \
	apt-get -y install libbrotli-dev

ENV CGO_ENABLED=1
ENV GOAMD64=$GOAMD64

WORKDIR /workspace
ADD go.mod go.sum ./
RUN go mod download

ADD . .
RUN go build \
		-o parapet-ingress-controller \
		-ldflags "-w -s -X main.version=$VERSION" \
		-tags=cbrotli \
		./cmd/parapet-ingress-controller

FROM debian:bullseye-slim

RUN apt-get update && \
	apt-get -y install libbrotli1 ca-certificates && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=0 /workspace/parapet-ingress-controller ./
ENTRYPOINT ["/app/parapet-ingress-controller"]
