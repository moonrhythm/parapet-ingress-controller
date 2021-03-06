# parapet-ingress-controller

Parapet Ingress Controller use [parapet](https://github.com/moonrhythm/parapet) framework
to create Kubernetes ingress controller.

## Deploy

See deploy config at [deploy](https://github.com/moonrhythm/parapet-ingress-controller/tree/master/deploy)
directory.

## Usage

Create ingress with an annotation `kubernetes.io/ingress.class: parapet`

### Example

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: parapet
    parapet.moonrhythm.io/hsts: preload
    parapet.moonrhythm.io/redirect: |
      example.com: https://www.example.com
    parapet.moonrhythm.io/redirect-https: "true"
  name: ingress
spec:
  rules:
  - host: www.example.com
    http:
      paths:
      - backend:
          serviceName: example
          servicePort: http
      - path: /assets/
        backend:
          serviceName: gcs
          servicePort: https
  - host: api.example.com
    http:
      paths:
      - backend:
          serviceName: api-example
          servicePort: http
  tls:
  - secretName: tls-www
  - secretName: tls-api
```

## Plugins

Plugins use annotation in ingress to config.

See supported annotations in [plugin](https://github.com/moonrhythm/parapet-ingress-controller/tree/master/plugin)
directory.

## Metrics

Parapet ingress controller support prometheus metrics by add prometheus annotations to pod template.

```yaml
annotations:
  prometheus.io/port: "9187"
  prometheus.io/scrape: "true"
```

### Supported Metrics

#### Ingress Metrics

- parapet_requests{host, status, method, ingress_name, ingress_namespace, service_type, service_name}
- parapet_backend_connections{addr}
- parapet_backend_network_read_bytes{addr}
- parapet_backend_network_write_bytes{addr}

#### Metrics directly use from parapet

- parapet_connections{state}
- parapet_network_request_bytes{}
- parapet_network_response_bytes{}

## License

MIT
