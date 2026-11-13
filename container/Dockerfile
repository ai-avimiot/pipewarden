## ---------------------------------------------------------------------------
## PipeWarden — orchestrator image
##
## Three images make up PipeWarden:
##   1. nfw (this image)   — orchestrator + act + pre-cached actions
##   2. nfw-proxy          — mitmproxy transparent proxy (see proxy/)
##   3. nfw-runner         — act-compatible runner with iproute2 (see runner/)
##
## Design goals:
##   - Minimal runtime deps — no build tools or test frameworks
##   - Quick startup — parallelized setup, pre-cached actions, pre-pulled images
## ---------------------------------------------------------------------------

# Stage 1: grab the static Docker CLI binary
# Pinned by digest (tag kept for readability; Dependabot refreshes it).
# To refresh manually: docker buildx imagetools inspect docker:<tag>
FROM docker:29-cli@sha256:5a7af0dcb0e46c803efe9b45371dd21cb500e5b4453250394ac6f06d49b6e6f1 AS docker-cli

# Stage 2: build act from its release tag. Upstream release binaries lag far
# behind Go and x/* security fixes, so rebuild with a current toolchain and
# the patched module versions below.
# Pinned by digest (tag kept for readability; Dependabot refreshes it).
FROM --platform=$BUILDPLATFORM golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d AS act-build
ARG ACT_VERSION="0.2.97"
ARG ACT_COMMIT="2540ba6c49"
RUN git clone --depth 1 -b "v${ACT_VERSION}" https://github.com/nektos/act.git /src/act \
    && cd /src/act \
    && git rev-parse HEAD | grep -q "^${ACT_COMMIT}" \
    && go get \
         github.com/go-git/go-git/v5@v5.19.3 \
         github.com/klauspost/compress@v1.20.4 \
         github.com/moby/go-archive@v0.3.3 \
         github.com/moby/sys/user@v0.5.0 \
         golang.org/x/crypto@v0.58.0 \
         golang.org/x/net@v0.62.0 \
         golang.org/x/text@v0.44.0 \
    && go mod tidy \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
         -ldflags "-s -w -X main.version=${ACT_VERSION}" -o /out/act .

# Stage 3: pre-cache common GitHub Actions
# Pinned by digest (tag kept for readability; Dependabot refreshes it).
# To refresh manually: docker buildx imagetools inspect ubuntu:<tag>
FROM ubuntu:26.04@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96 AS act-download
RUN apt-get update -qq && apt-get install -y -qq git

# Pre-cache common GitHub Actions so act doesn't clone them at runtime.
# Only cache actions actually used in demo workflows (checkout + setup-node).
# act stores actions as <org>-<repo>@<ref> directories.
# After cloning, strip everything except action.yml + dist/ (the only files
# act needs at runtime). Saves ~23MB vs caching all language setup actions.
RUN mkdir -p /opt/act-cache \
    && git clone --depth 1 -b v4 https://github.com/actions/checkout.git      /opt/act-cache/actions-checkout@v4 \
    && git clone --depth 1 -b v4 https://github.com/actions/setup-node.git    /opt/act-cache/actions-setup-node@v4 \
    && rm -rf /opt/act-cache/*/.git \
    && for dir in /opt/act-cache/actions-*; do \
         find "$dir" -mindepth 1 -maxdepth 1 \
           ! -name 'action.yml' ! -name 'action.yaml' ! -name 'dist' \
           -exec rm -rf {} + ; \
       done

# Stage 4: runtime image — same Ubuntu LTS (and digest) as build stage.
FROM ubuntu:26.04@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96

# Avoid interactive prompts during apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Install only what we need at runtime. The base image's unused pebble binary
# is removed: it ships with its own lagging Go stdlib.
#
#   python3 + python3-yaml     — run orchestrator scripts (apt, no pip needed)
#   python3-dnspython          — IP enrichment via Team Cymru DNS (replaces dig)
#   openssl                    — generate CA cert
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
       python3 python3-yaml python3-dnspython openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/bin/pebble

# Static Docker CLI from official image (~60MB vs ~100MB from apt)
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

# act binary for running GitHub Actions workflows locally (~40MB)
COPY --from=act-build /out/act /usr/local/bin/act

# Pre-cached GitHub Actions (avoids git clone at runtime)
COPY --from=act-download /opt/act-cache /opt/act-cache

WORKDIR /nfw

# Copy project files
COPY container/entrypoint.sh .
COPY scripts/ scripts/
COPY policy/ policy/
COPY proxy/ proxy/

ENTRYPOINT ["bash", "entrypoint.sh"]
