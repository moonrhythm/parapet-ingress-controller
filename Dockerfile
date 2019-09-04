FROM gcr.io/moonrhythm-containers/alpine:3.10

RUN mkdir -p /app
WORKDIR /app

COPY parapet-ingress-controller ./
ENTRYPOINT ["/app/parapet-ingress-controller"]
