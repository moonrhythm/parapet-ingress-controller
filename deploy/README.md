# Deploy

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
