FROM gcr.io/moonrhythm-containers/alpine:3.10

RUN mkdir -p /app
WORKDIR /app
ENV GODEBUG tls13=1

COPY parapet-ingress-controller ./
ENTRYPOINT ["/app/parapet-ingress-controller"]
