## PipeWarden runner — minimal act-compatible runner with iproute2 for route switching.
## Uses Ubuntu LTS base for minimal size. Tools (Node.js, Python, etc.) are downloaded
## on first run and cached in Docker volumes for subsequent runs.
# To digest-pin: docker buildx imagetools inspect ubuntu:26.04
# then use: FROM ubuntu:26.04@sha256:<digest>
FROM ubuntu:26.04

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
