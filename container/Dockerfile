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
FROM docker:29-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb AS docker-cli

# Stage 2: build act from its release tag. Upstream release binaries lag far
# behind Go and x/* security fixes, so rebuild with a current toolchain and
# the patched module versions below. go-archive 0.3 moved its compression
# constants; act passes the zero value (uncompressed), so the field is dropped.
# Pinned by digest (tag kept for readability; Dependabot refreshes it).
FROM --platform=$BUILDPLATFORM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS act-build
ARG ACT_VERSION="0.2.89"
ARG ACT_COMMIT="4f41128141"
RUN git clone --depth 1 -b "v${ACT_VERSION}" https://github.com/nektos/act.git /src/act \
    && cd /src/act \
    && git rev-parse HEAD | grep -q "^${ACT_COMMIT}" \
    && go get \
         github.com/go-git/go-git/v5@v5.19.2 \
         github.com/klauspost/compress@v1.18.7 \
         github.com/moby/go-archive@v0.3.3 \
         github.com/moby/sys/user@v0.4.1 \
         golang.org/x/crypto@v0.57.0 \
         golang.org/x/net@v0.60.0 \
         golang.org/x/text@v0.42.0 \
    && sed -i -e '/compression := archive.Uncompressed/d' \
              -e '/Compression: *compression,/d' pkg/container/docker_build.go \
    && go mod tidy \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
         -ldflags "-s -w -X main.version=${ACT_VERSION}" -o /out/act .

# Stage 3: pre-cache common GitHub Actions
# Pinned by digest (tag kept for readability; Dependabot refreshes it).
# To refresh manually: docker buildx imagetools inspect ubuntu:<tag>
FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944 AS act-download
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
FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944

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
