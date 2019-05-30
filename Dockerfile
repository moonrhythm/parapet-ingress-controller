FROM gcr.io/moonrhythm-containers/alpine:3.9

RUN mkdir -p /app
WORKDIR /app

COPY parapet-ingress-controller ./
ENTRYPOINT ["/app/parapet-ingress-controller"]
