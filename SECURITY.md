# Security

## Reporting

Open a [private security advisory](https://github.com/JackFurton/portcullis/security/advisories/new).
Please do not open a public issue for a vulnerability.

This is a personal project with no support commitment. I will respond when I
can, and I would rather hear about a problem late than not at all.

## What this service is responsible for

It decides whether a request proceeds, and it tells the upstream who is
calling. A bug in it is an authorization bypass. In particular:

- accepting a token that should not verify
- matching a request against the wrong rule
- letting a caller influence the identity headers the upstream trusts
- allowing a request when it could not reach a decision

All four have tests. If you find a way around any of them, that is a
vulnerability rather than a bug.

## What it is not responsible for

- **Transport security.** The gRPC listener is plaintext. Under a mesh the
  sidecar provides mTLS; standalone, put it on a trusted network or in front of
  a TLS terminator.
- **Which requests reach it.** Under Istio, the `AuthorizationPolicy` selects
  what gets sent for a decision. Anything it does not select is never seen
  here, so that selector is part of the security boundary.
- **Token issuance.** Tokens come from your identity provider. `cmd/demoidp`
  mints tokens for anyone who can reach it and refuses to start without a flag
  saying you understand that. It is for the demo and nothing else.
- **Revocation.** A JWT is valid until it expires. Verification results are
  cached for at most 60 seconds and expiry is enforced on every cache hit, so
  the cache never extends a token's life, but neither does anything here shorten
  it. Keep token lifetimes short.

## Design notes

- Accepted algorithms come from configuration, never from the token, and are
  applied before any key lookup. Symmetric algorithms are not supported at all.
- The `iss` claim is read before verification for exactly one purpose: choosing
  which configured issuer to verify against. The key set URL always comes from
  the policy file.
- Denials name a coarse reason. The specific failed check is logged, not
  returned, because a 401 that names it tells whoever is probing what to try
  next.
- Metrics carry no tenant or subject label. Both are attacker influenced and
  unbounded.
