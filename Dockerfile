FROM debian:buster-slim

RUN apt update && apt install -y \
	brotli \
	libbrotli-dev \
	&& rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app
WORKDIR /app

COPY parapet-ingress-controller ./
ENTRYPOINT ["/app/parapet-ingress-controller"]
