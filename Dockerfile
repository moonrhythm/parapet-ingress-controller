FROM golang:1.20.0-alpine3.17

ARG VERSION

RUN apk --no-cache add git build-base brotli-dev

ENV CGO_ENABLED=1
ENV GOAMD64=v3

WORKDIR /workspace
ADD go.mod go.sum ./
RUN go mod download

ADD . .
RUN go build \
		-o parapet-ingress-controller \
		-ldflags "-w -s -X main.version=$VERSION" \
		-tags=cbrotli \
		./cmd/parapet-ingress-controller

FROM alpine:3.17

RUN apk add --no-cache ca-certificates tzdata brotli

WORKDIR /app

COPY --from=0 /workspace/parapet-ingress-controller ./
ENTRYPOINT ["/app/parapet-ingress-controller"]
