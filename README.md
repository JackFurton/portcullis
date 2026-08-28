# portcullis

[![CI](https://github.com/JackFurton/portcullis/actions/workflows/ci.yml/badge.svg)](https://github.com/JackFurton/portcullis/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/JackFurton/portcullis.svg)](https://pkg.go.dev/github.com/JackFurton/portcullis)

An external authorization service for Envoy and Istio, in Go.

Envoy asks it about every request. It verifies the bearer token against the
issuer's published keys, decides against an ordered policy, and tells the
upstream who is calling. Default deny, fail closed, and the identity headers it
sets cannot be forged by the caller.

```yaml
rules:
  - name: health
    match: {pathsExact: [/healthz], methods: [GET]}
    allow: {public: true}

  - name: events-read
    match: {pathPrefixes: [/v1/events], methods: [GET]}
    allow:
      issuers: [corp]
      scopes: [events.read]
      tenants: ["*"]        # any tenant, but the token must name one

  - name: admin
    match: {pathPrefixes: [/v1/admin]}
    allow:
      issuers: [corp]
      scopes: [admin]
      tenants: [acme, globex]
```

## Try it in about two minutes

```bash
make demo-up     # Envoy, portcullis, a demo identity provider, an echo upstream
make demo-try    # walk through the allow and deny cases
make demo-down
```

Requires `docker` and `docker compose`. Nothing else, and no account anywhere.

```
Open route, no token:
  200  GET    /healthz                     public rule

Protected route:
  401  GET    /v1/events                   no token missing_token
  200  GET    /v1/events                   valid, events.read
  403  POST   /v1/events                   read token, write route insufficient_scope
  401  GET    /v1/events                   expired token invalid_token

Tenant scoped route:
  200  GET    /v1/admin/users              acme is allowed
  403  GET    /v1/admin/users              initech is not wrong_tenant
  403  GET    /v1/admin/users              reader has no admin scope insufficient_scope
```

`make smoke` runs the same stack and asserts every one of those outcomes. It is
what CI runs, because the failure that matters in a service like this is a
change that quietly turns a deny into an allow.

## What it guards against

**Algorithm confusion.** The accepted algorithms come from the policy file and
are handed to the parser before a key is looked up. A token whose header says
`HS256`, MACed with the issuer's public key, is rejected at parse time rather
than verified against a key it was never meant for. `alg: none` never parses,
and symmetric algorithms are not in the allowlist at all.

**Choosing a key from the token.** The `iss` claim is read unverified for
exactly one purpose: picking which configured issuer to verify against. That
issuer's `jwksURL` comes from the policy file, never from the token or from
discovery, and verification then requires `iss` to equal the configured value.
A token cannot point the service at a key set of its choosing.

**Forged identity headers.** Everything in the `x-portcullis-` namespace is
stripped from the inbound request. Headers the decision sets are overwritten;
headers it does not set are removed. A caller sending `x-portcullis-tenant:
acme` gets it replaced or dropped, never passed through.

**Paths that mean two things.** A rule granting `/v1/public` is only meaningful
if the path it matched is the path the router will use. Encoded slashes, dot
segments, backslashes and empty segments are rejected rather than cleaned up,
because cleaning them up is where the two readings diverge. Envoy is configured
to reject them too; neither check depends on the other being enabled.

**Prefixes that overreach.** A prefix has to end at a segment boundary, so a
rule for `/v1/admin` does not also match `/v1/administrators`.

**Claims that are not header safe.** A claim carrying a newline becomes a
header injection into whatever is downstream. Control characters and oversized
values fail verification.

**A JWKS endpoint used as an amplifier.** An unknown `kid` triggers a refetch,
which is how a key rotation is picked up within seconds. That refetch is rate
limited, so a stream of tokens carrying random `kid` values cannot turn this
service into a denial of service against the identity provider. Scheduled
refreshes are not rate limited, so a rotation is never delayed by an attacker.

**An identity provider having a bad day.** A failed refresh keeps serving the
cached key set. Denying every request because the JWKS endpoint is briefly
unreachable makes someone else's incident into yours, and the keys almost
certainly have not changed.

**A typo taking the gateway down.** A policy that does not validate is never
applied. On startup that is a hard failure; on reload the previous policy stays
in force and a counter goes up. Unknown fields are errors, because a
misspelled `tenants` is a rule that silently stops checking the tenant.

## Decisions and reasons

Every outcome carries a stable reason code. It appears in the deny body, in the
logs, on `portcullis_decisions_total`, and in Envoy's access log through
dynamic metadata.

| Reason | Status | Meaning |
| --- | --- | --- |
| `allowed`, `allowed_public` | 200 | The rule permitted it |
| `no_matching_rule` | 403 | Nothing matched, so the default deny applied |
| `rule_denies` | 403 | A rule matched and has no `allow` block |
| `malformed_path` | 400 | The path could not be reduced to one meaning |
| `missing_token` | 401 | A protected rule and no bearer token |
| `invalid_token` | 401 | Signature, expiry, audience or issuer check failed |
| `unknown_issuer` | 401 | The token's issuer is not configured |
| `issuer_not_allowed` | 403 | Configured, but not for this rule |
| `insufficient_scope` | 403 | The token is missing a required scope |
| `wrong_tenant`, `wrong_subject` | 403 | Identity does not match the rule |
| `internal_error` | 503 | No decision could be reached; `failureMode` applied |

A rule in shadow mode reports the reason it would have denied, with the request
allowed. See below.

The reason is deliberately coarse in the response and specific in the logs. A
401 that names which check failed tells whoever is probing which one to work on
next.

## Rolling out a policy without breaking people

The scary part of authorization is the first day it says no. Shadow mode makes
that a measurement instead of a deploy:

```yaml
mode: shadow          # policy default

rules:
  - name: admin
    mode: enforce     # this one is already trusted
    match: {pathPrefixes: [/v1/admin]}
    allow: {scopes: [admin], tenants: [acme]}

  - name: events
    match: {pathPrefixes: [/v1/events]}
    allow: {scopes: [events.read], tenants: ["*"]}
```

A shadowed rule allows the request, logs what it would have done at info level,
counts it under `portcullis_decisions_total{decision="shadow_deny"}`, and marks
the decision `shadow` in dynamic metadata so an access log can attribute it to
a route.

Identity headers are still forwarded exactly as they will be under
enforcement, so the shadow run tells you something about what enforcing will
actually do rather than only about who would have been refused.

Watch `shadow_deny` until it reaches zero, or until everything left in it is
something you meant to refuse. Then switch the rule to `enforce`.

Shadow never applies to `internal_error`. Whether the service could reach a
decision is a different question from what the decision would have been, and
`failureMode` already answers it.

## Optional authentication

A `public: true` rule allows the request with no token. If a token is present
and valid, the identity is still forwarded, so an open endpoint can know who is
calling when it can. A token that fails verification does not turn the request
into a denial: making it one would turn every public endpoint into an oracle
for whether a forged token validates.

## Cost per request

This service runs on every request through the mesh, so its own latency is
everyone's latency. Measured on an M5 with `go test ./internal/authz -bench .`,
covering the whole `Check` call: matching the rule, verifying the signature,
checking the claims and building the response.

| Path | Time | Allocations |
| --- | --- | --- |
| Allowed, token already verified | 2.5 µs | 59 |
| Allowed, cold cache | 29.7 µs | 211 |
| Denied on scope | 3.3 µs | 53 |
| Public rule, no token | 0.6 µs | 20 |
| Protected rule, no token | 1.9 µs | 41 |

The gap between the first two rows is one RSA verification. A caller reuses a
token for its whole lifetime, so results are cached: keyed by a hash of the
token, never the token itself, bounded and LRU evicted, flushed whenever the
policy reloads. Expiry is enforced on every hit and a result is reused for at
most 60 seconds, so the cache can neither outlive a token nor keep serving a
decision made under an issuer configuration that has since changed.

`--token-cache-size 0` disables it, at roughly twelve times the CPU per
request.

## Configuration

```bash
portcullis --policy /etc/portcullis/policy.yaml \
           --grpc-addr :9191 \
           --admin-addr :9192 \
           --token-cache-size 10000
```

`--check` validates the policy and exits, which is worth running in CI
(`make check-policy`). `--version` prints the build and the commit it came
from.

The policy file is watched and reloaded in place. It watches the containing
directory rather than the file, because a ConfigMap mounted into a pod is a
symlink into a `..data` directory that Kubernetes swaps wholesale; watching the
file works on a laptop and silently never fires in a cluster.

The admin port serves `/metrics`, `/healthz` and `/readyz`. Metrics carry no
tenant or subject label: both are attacker influenced and unbounded, and a
label like that is how a metrics endpoint takes down the cluster it monitors.

## Deploying

```bash
kubectl apply -f deploy/kubernetes/portcullis.yaml
```

Images are published to `ghcr.io/jackfurton/portcullis` on every tag, for
`linux/amd64` and `linux/arm64`.

`deploy/kubernetes/portcullis.yaml` has the Deployment, Service, ConfigMap and
PodDisruptionBudget. `deploy/istio/` has the mesh `extensionProvider` and the
`AuthorizationPolicy` that routes traffic through it, with notes on the two
independent failure settings that decide what happens when something breaks.

## Development

```bash
make test    # unit tests with -race
make lint
make smoke   # the full stack, with every decision asserted
```

The tests mint real tokens against a real key set and verify real signatures,
including the forged ones. The bugs worth catching in this service live in
exactly the code a stub verifier would replace.

## Status

Working and tested, but young, and the policy format may change before v1.

Implemented: HTTP bearer tokens, JWKS with rotation, per-rule issuer, tenant,
subject and scope checks, hot policy reload, Prometheus metrics.

Not implemented: mTLS on the gRPC listener, client certificate identity,
opaque token introspection, per-tenant rate limiting. See the
[open issues](https://github.com/JackFurton/portcullis/issues) for what is
planned and why.

Security notes, and what this service is and is not responsible for, are in
[SECURITY.md](SECURITY.md).

## License

Apache 2.0.
