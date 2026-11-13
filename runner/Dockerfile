## PipeWarden runner — minimal act-compatible runner with iproute2 for route switching.
## Uses Ubuntu LTS base for minimal size. Tools (Node.js, Python, etc.) are downloaded
## on first run and cached in Docker volumes for subsequent runs.
# Pinned by digest (tag kept for readability). To refresh after a version bump
# (Dependabot also does this): docker buildx imagetools inspect ubuntu:<tag>
FROM ubuntu:26.04@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime essentials (pebble is unused and ships a lagging Go stdlib)
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
       iproute2 \
       iptables \
       ca-certificates \
       curl \
       git \
       sudo \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/bin/pebble

# Create runner user (required by act)
RUN useradd -m -s /bin/bash runner \
    && echo "runner ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER runner
WORKDIR /home/runner
