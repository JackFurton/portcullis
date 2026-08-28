# Running under Istio

Two pieces: the mesh has to know the provider exists, and an `AuthorizationPolicy`
has to send traffic to it.

## 1. Register the provider

The provider lives in the mesh config, which means patching the `IstioOperator`
or the `istio` ConfigMap rather than applying a resource. With `istioctl`:

```bash
istioctl install -f mesh-config.yaml
```

Or patch an existing install:

```bash
kubectl -n istio-system get configmap istio -o yaml
# merge the extensionProviders block from mesh-config.yaml into data.mesh
```

## 2. Point traffic at it

`authorization-policy.yaml` uses `action: CUSTOM`, which is what routes a
request through an external provider. The `rules` in that policy select which
requests are sent for a decision; everything they select is decided by
portcullis, and everything they do not select never reaches it.

That selection is a real security boundary and it is easy to get wrong. A
`notPaths` exclusion added to skip a health check also skips authorization for
anything that happens to match it.

## Failure behavior

Two independent settings decide what happens when something breaks, and they
answer different questions:

- `failureMode` in the policy file: portcullis could not reach a decision, for
  example because an issuer's JWKS endpoint is unreachable. Defaults to `deny`.
- Istio's own behavior when the provider is unreachable: the sidecar fails the
  request closed. There is no setting here that makes it open, which is the
  right default and worth knowing before an incident.
