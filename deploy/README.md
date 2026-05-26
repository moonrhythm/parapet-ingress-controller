# Deploy

These manifests are **image-agnostic** — they work with either implementation.
Pick the image stream in `deployment.yaml` / `daemonset.yaml`:

- Go (parapet): `…/parapet-ingress-controller:<tag>`
- Rust (Pingora): `…/parapet-ingress-controller:rust-<sha>`

Both honor the same env vars and RBAC (see [`../SPEC.md`](../SPEC.md)).

```bash
$ kubectl apply -f https://raw.githubusercontent.com/moonrhythm/parapet-ingress-controller/master/deploy/00-namespace.yaml

# for cluster ingress
$ kubectl apply -f https://raw.githubusercontent.com/moonrhythm/parapet-ingress-controller/master/deploy/role-cluster.yaml

# for namespaced ingress
$ kubectl apply -f https://raw.githubusercontent.com/moonrhythm/parapet-ingress-controller/master/deploy/role-namespaced.yaml

$ kubectl apply -f https://raw.githubusercontent.com/moonrhythm/parapet-ingress-controller/master/deploy/01-serviceaccount.yaml

$ kubectl apply -f https://raw.githubusercontent.com/moonrhythm/parapet-ingress-controller/master/deploy/02-service.yaml

$ kubectl apply -f https://raw.githubusercontent.com/moonrhythm/parapet-ingress-controller/master/deploy/deployment.yaml
```
