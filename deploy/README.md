# Deploy

Set the image in `deployment.yaml` / `daemonset.yaml`:

- `…/parapet-ingress-controller:<tag>`

Env vars and RBAC are documented in [`../SPEC.md`](../SPEC.md).

The WAF is off by default. `deployment.yaml` / `daemonset.yaml` carry a
commented-out opt-in block (`WAF_ENABLED` + `WAF_GEOIP_DB` + `WAF_ASN_DB`); the
images bake both IPLocate DBs at `/geoip/ip-to-country.mmdb` and
`/geoip/ip-to-asn.mmdb`, so country (`request.country`) and ASN (`request.asn`)
filtering work without mounting anything. See [`../WAF.md`](../WAF.md).

```bash
$ kubectl apply -f https://raw.githubusercontent.com/moonrhythm/parapet-ingress-controller/main/deploy/00-namespace.yaml

# for cluster ingress
$ kubectl apply -f https://raw.githubusercontent.com/moonrhythm/parapet-ingress-controller/main/deploy/role-cluster.yaml

# for namespaced ingress
$ kubectl apply -f https://raw.githubusercontent.com/moonrhythm/parapet-ingress-controller/main/deploy/role-namespaced.yaml

$ kubectl apply -f https://raw.githubusercontent.com/moonrhythm/parapet-ingress-controller/main/deploy/01-serviceaccount.yaml

$ kubectl apply -f https://raw.githubusercontent.com/moonrhythm/parapet-ingress-controller/main/deploy/02-service.yaml

$ kubectl apply -f https://raw.githubusercontent.com/moonrhythm/parapet-ingress-controller/main/deploy/deployment.yaml
```
