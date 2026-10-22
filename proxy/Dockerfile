# Pinned by digest so the base image is immutable (a tag can be repointed at a
# new image — a supply-chain risk). The tag is kept for readability; the digest
# is authoritative. To refresh after a version bump (Dependabot also does this):
#   docker buildx imagetools inspect mitmproxy/mitmproxy:<tag>
FROM mitmproxy/mitmproxy:12.3.0@sha256:c8a3753de11fd8266afeb103e163f7b7ac6a4a568a707fa2e15b23d20acf4eba

USER root

# Install iptables + iproute2 for transparent proxying, and pip deps in one layer.
# Use the hash-pinned lock file when available (supply-chain security).
# To populate proxy/requirements-lock.txt, run: ./scripts/update-lock-files.sh
COPY proxy/requirements.txt /proxy-requirements.txt
COPY proxy/requirements-lock.txt /proxy-requirements-lock.txt
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends iptables iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && if grep -qE "^[^#[:space:]]" /proxy-requirements-lock.txt 2>/dev/null; then \
         pip install --no-cache-dir --require-hashes -r /proxy-requirements-lock.txt; \
       else \
         echo "WARNING: proxy/requirements-lock.txt has no pinned packages." \
              "Run ./scripts/update-lock-files.sh to enable hash verification."; \
         pip install --no-cache-dir -r /proxy-requirements.txt; \
       fi

# Bake the policy Python package (changes less often)
COPY policy/ /policy/

# Copy addon code + entrypoint
COPY proxy/addon.py /addon.py
COPY proxy/dns_server.py /dns_server.py
COPY proxy/proxy-entrypoint.sh /proxy-entrypoint.sh
RUN chmod +x /proxy-entrypoint.sh

ENV POLICY_FILE=/policy.yml \
    MODE=monitor \
    LOG_PATH=/var/log/connections.jsonl

EXPOSE 8080 53/udp

CMD ["/proxy-entrypoint.sh"]
