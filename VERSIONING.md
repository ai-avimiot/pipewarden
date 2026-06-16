# Versioning

PipeWarden follows [Semantic Versioning](https://semver.org/) and publishes
floating tags for convenience.

## Tags

| Tag | Mutable? | Points to | Use for |
|-----|----------|-----------|---------|
| `vX.Y.Z` (e.g. `v1.0.7`) | no | one exact release | **production / supply-chain integrity** — pin to this (or a commit SHA) |
| `vX` (e.g. `v1`) | yes | latest `X.Y.Z` within that major | tracking fixes + features without breaking changes |
| `latest` | yes | the newest release across **all** majors | demos and quick starts (not recommended for production) |

The same scheme applies to the container images
(`ghcr.io/ai-avimiot/pipewarden`, `…/pipewarden-proxy`): `X.Y.Z`, `X.Y`, and
`latest` (where `latest` is the newest released image).

## What bumps the number

- **Patch** (`x.y.Z`) — bug fixes and doc changes; no behavior change.
- **Minor** (`x.Y.z`) — new, backward-compatible features (e.g. a new optional
  action input, a new policy field with a safe default).
- **Major** (`X.y.z`) — **breaking changes**, for example:
  - policy-schema changes that invalidate existing `network-policy.yml` files,
  - renaming/removing an action input or output,
  - changing a default that can break existing pipelines (e.g. default mode).

When a breaking change ships, we cut a new major (e.g. `v2`) and publish a new
floating `v2` tag. `latest` then advances to it; `v1` keeps tracking the latest
`1.x` so pinned consumers are not broken.

## Recommendation

- **Production / security-sensitive pipelines:** pin to an exact `vX.Y.Z` or a
  commit SHA. PipeWarden is a supply-chain tool — a mutable tag is a moving
  dependency.
- **Convenience within a major:** use `@v1` to get fixes and features without
  breaking changes.
- **`@latest`** follows everything, including future majors — convenient for
  demos, but it can pull in breaking changes, so avoid it in production.
