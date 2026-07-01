## PipeWarden runner — minimal act-compatible runner with iproute2 for route switching.
## Uses Ubuntu LTS base for minimal size. Tools (Node.js, Python, etc.) are downloaded
## on first run and cached in Docker volumes for subsequent runs.
# Pinned by digest (tag kept for readability). To refresh after a version bump
# (Dependabot also does this): docker buildx imagetools inspect ubuntu:<tag>
FROM ubuntu:26.04@sha256:53958ec7b67c2c9355df922dd08dbf0360611f8c3cdb656875e81873db9ffdba

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime essentials
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
       iproute2 \
       iptables \
       ca-certificates \
       curl \
       git \
       sudo \
    && rm -rf /var/lib/apt/lists/*

# Create runner user (required by act)
RUN useradd -m -s /bin/bash runner \
    && echo "runner ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER runner
WORKDIR /home/runner
