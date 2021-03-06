FROM alpine:3.13

RUN apk add --no-cache ca-certificates tzdata brotli

RUN mkdir -p /app
WORKDIR /app

COPY parapet-ingress-controller ./
ENTRYPOINT ["/app/parapet-ingress-controller"]
