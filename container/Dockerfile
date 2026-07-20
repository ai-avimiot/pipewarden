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
FROM docker:29-cli@sha256:be132a9f282288de4afaf63379dff75711fda0147c6b72a9df44e51841402144 AS docker-cli

# Stage 2: download act binary and pre-cache common GitHub Actions
# Pinned by digest (tag kept for readability; Dependabot refreshes it).
# To refresh manually: docker buildx imagetools inspect ubuntu:<tag>
FROM ubuntu:26.04@sha256:53958ec7b67c2c9355df922dd08dbf0360611f8c3cdb656875e81873db9ffdba AS act-download
ARG ACT_VERSION="0.2.84"
RUN apt-get update -qq && apt-get install -y -qq curl git \
    && curl -fsSL "https://github.com/nektos/act/releases/download/v${ACT_VERSION}/act_Linux_x86_64.tar.gz" \
       | tar -xz -C /usr/local/bin act \
    && chmod +x /usr/local/bin/act

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

# Stage 3: runtime image — same Ubuntu LTS (and digest) as build stage.
FROM ubuntu:26.04@sha256:53958ec7b67c2c9355df922dd08dbf0360611f8c3cdb656875e81873db9ffdba

# Avoid interactive prompts during apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Install only what we need at runtime:
#   python3 + python3-yaml     — run orchestrator scripts (apt, no pip needed)
#   python3-dnspython          — IP enrichment via Team Cymru DNS (replaces dig)
#   openssl                    — generate CA cert
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
       python3 python3-yaml python3-dnspython openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Static Docker CLI from official image (~60MB vs ~100MB from apt)
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

# act binary for running GitHub Actions workflows locally (~40MB)
COPY --from=act-download /usr/local/bin/act /usr/local/bin/act

# Pre-cached GitHub Actions (avoids git clone at runtime)
COPY --from=act-download /opt/act-cache /opt/act-cache

WORKDIR /nfw

# Copy project files
COPY container/entrypoint.sh .
COPY scripts/ scripts/
COPY policy/ policy/
COPY proxy/ proxy/

ENTRYPOINT ["bash", "entrypoint.sh"]
