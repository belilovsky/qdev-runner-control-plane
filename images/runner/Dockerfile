# syntax=docker/dockerfile:1.7
ARG RUNNER_VERSION=2.337.0
ARG RUNNER_SHA256=70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613
ARG NPM_VERSION=11.19.1
ARG NPM_SHA512=cedb312b1b7f92421a02cfb68b4194e88f8346651dacd6acc5364a25ef5309d4a32b19616a1ff8aff865e7280c0fa5c0835a99f5cd93368991e2a80ec9da75d2
ARG SYSTEM_NPM_VERSION=12.0.2
ARG SYSTEM_NPM_SHA512=b885e890b9418fa1693544d05f53e64f9a73ec194837d4258b15fecdd692347b1dd2a517b1b0cbaf9d31cd8e92c3b70956bd2ecc72833a57b4b3098f5bfa7943
ARG BRACE_EXPANSION_VERSION=5.0.9
ARG BRACE_EXPANSION_SHA512=49c43822ebc8105d533253fb66dfaf8c9ffff7394f6f64837315b13376e4f2ceade8619d27b28ed5d09c4e274e3c929e3d6df42c4ff6713ef00b23e1a3dfd6c6
ARG IP_ADDRESS_VERSION=10.3.1
ARG IP_ADDRESS_SHA512=d5ef5dde46fdecd1c94c8243656f6b2aa5b687af9d15ae740f2d1fa4f48c429d800e37b982f2ac5e67622ba770639b7be93693b79f8fe4dd58fcba13a08c4fea
ARG TAR_VERSION=7.5.21
ARG TAR_SHA512=5dd86d0af94ccb0c31a425bc604ab794e5c126950f4d1d8e1c77302cf3b71f0b09a8e1dad8e93fa09eebb86ce9f89acaa113d50b327001d123a8b5bfbcd44f1c

FROM ubuntu@sha256:1e0a86e57d247923571b75e0aaf48a1449cf8c543d51fb3e07a4a7d7bfa79316 AS base
ARG RUNNER_VERSION
ARG RUNNER_SHA256
ARG NPM_VERSION
ARG NPM_SHA512
ENV DEBIAN_FRONTEND=noninteractive
COPY install-pinned-npm.sh /usr/local/bin/install-pinned-npm
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl git git-lfs gnupg jq lsb-release openssh-client python3 python3-pip \
      python3-venv rsync unzip xz-utils zip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1001 --shell /bin/bash runner \
    && mkdir -p /home/runner/actions-runner \
    && curl --fail --location --retry 5 \
      "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
      --output /tmp/runner.tar.gz \
    && echo "${RUNNER_SHA256}  /tmp/runner.tar.gz" | sha256sum --check - \
    && tar -xzf /tmp/runner.tar.gz -C /home/runner/actions-runner \
    && rm /tmp/runner.tar.gz \
    && chmod 0555 /usr/local/bin/install-pinned-npm \
    && /usr/local/bin/install-pinned-npm /home/runner/actions-runner/externals/node20 "${NPM_VERSION}" "${NPM_SHA512}" \
    && /usr/local/bin/install-pinned-npm /home/runner/actions-runner/externals/node24 "${NPM_VERSION}" "${NPM_SHA512}" \
    && /home/runner/actions-runner/bin/installdependencies.sh \
    && chown -R runner:runner /home/runner
COPY entrypoint.sh /usr/local/bin/qdev-runner-entrypoint
RUN chmod 0555 /usr/local/bin/qdev-runner-entrypoint
USER runner
WORKDIR /home/runner/actions-runner
ENTRYPOINT ["/usr/local/bin/qdev-runner-entrypoint"]

FROM base AS general
USER root
# PostgreSQL's ssl-cert dependency creates a host-local snakeoil identity during
# package installation. Disposable CI clusters do not use it, so never publish
# that generated private key in the immutable runner image.
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-16 \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f \
         /etc/ssl/private/ssl-cert-snakeoil.key \
         /etc/ssl/certs/ssl-cert-snakeoil.pem \
    && test ! -e /etc/ssl/private/ssl-cert-snakeoil.key \
    && test ! -e /etc/ssl/certs/ssl-cert-snakeoil.pem \
    && for binary in initdb pg_ctl createdb dropdb psql pg_dump pg_restore; do \
         test -x "/usr/lib/postgresql/16/bin/${binary}"; \
       done \
    && /usr/lib/postgresql/16/bin/postgres --version | grep -Eq ' 16\.'
USER runner

# Playwright clients installed by browser jobs must stay in lockstep with the
# bundled Chromium revision. This is v1.62.1-noble-amd64, pinned by its OCI
# manifest digest rather than a mutable registry tag.
FROM mcr.microsoft.com/playwright@sha256:c091b21d9fae78c76e85cd4356431e9b018402f172a214fc7d7a5e9a7e29d8ac AS browser-build
ARG RUNNER_VERSION
ARG RUNNER_SHA256
ARG NPM_VERSION
ARG NPM_SHA512
ARG SYSTEM_NPM_VERSION
ARG SYSTEM_NPM_SHA512
ARG BRACE_EXPANSION_VERSION
ARG BRACE_EXPANSION_SHA512
ARG IP_ADDRESS_VERSION
ARG IP_ADDRESS_SHA512
ARG TAR_VERSION
ARG TAR_SHA512
COPY install-pinned-npm.sh /usr/local/bin/install-pinned-npm
COPY install-pinned-node-package.sh /usr/local/bin/install-pinned-node-package
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl git git-lfs jq lsb-release openssh-client python3 python3-pip python3-venv \
      rsync unzip xz-utils zip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1002 --shell /bin/bash runner \
    && mkdir -p /home/runner/actions-runner \
    && curl --fail --location --retry 5 \
      "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
      --output /tmp/runner.tar.gz \
    && echo "${RUNNER_SHA256}  /tmp/runner.tar.gz" | sha256sum --check - \
    && tar -xzf /tmp/runner.tar.gz -C /home/runner/actions-runner \
    && rm /tmp/runner.tar.gz \
    && chmod 0555 /usr/local/bin/install-pinned-npm /usr/local/bin/install-pinned-node-package \
    && /usr/local/bin/install-pinned-npm /home/runner/actions-runner/externals/node20 "${NPM_VERSION}" "${NPM_SHA512}" \
    && /usr/local/bin/install-pinned-npm /home/runner/actions-runner/externals/node24 "${NPM_VERSION}" "${NPM_SHA512}" \
    && /usr/local/bin/install-pinned-npm /usr "${SYSTEM_NPM_VERSION}" "${SYSTEM_NPM_SHA512}" \
    && /usr/local/bin/install-pinned-node-package /usr/lib/node_modules/npm/node_modules brace-expansion "${BRACE_EXPANSION_VERSION}" "${BRACE_EXPANSION_SHA512}" \
    && /usr/local/bin/install-pinned-node-package /usr/lib/node_modules/npm/node_modules ip-address "${IP_ADDRESS_VERSION}" "${IP_ADDRESS_SHA512}" \
    && /usr/local/bin/install-pinned-node-package /usr/lib/node_modules/npm/node_modules tar "${TAR_VERSION}" "${TAR_SHA512}" \
    && test "$(npm --version)" = "${SYSTEM_NPM_VERSION}" \
    && rm -rf /root/.npm \
    && test ! -e /root/.npm \
    && /home/runner/actions-runner/bin/installdependencies.sh \
    && chown -R runner:runner /home/runner
COPY entrypoint.sh /usr/local/bin/qdev-runner-entrypoint
RUN chmod 0555 /usr/local/bin/qdev-runner-entrypoint

# The upstream Playwright image contains deleted npm cache entries in an older
# layer. Trivy correctly scans layer history, so an ordinary `rm -rf` cannot
# remove those credentials from the published artifact. Export the final
# filesystem into a fresh single layer and restore only the required runtime
# metadata. This keeps the pinned Playwright payload while ensuring the
# published image has no inherited secret-bearing layer history.
FROM scratch AS browser
COPY --from=browser-build / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
LABEL org.opencontainers.image.version="24.04"
USER runner
WORKDIR /home/runner/actions-runner
ENTRYPOINT ["/usr/local/bin/qdev-runner-entrypoint"]

FROM base AS docker
ARG BUILDKIT_VERSION=0.32.2
ARG BUILDKIT_SHA256=2975d0f651ad96ba8b80b9992ae1f9a964f4408569af5b6dc36544165c3926af
USER root
RUN apt-get update && apt-get install -y --no-install-recommends docker.io docker-buildx docker-compose-v2 \
    && rm -rf /var/lib/apt/lists/* \
    && curl --fail --location --retry 5 \
      "https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz" \
      --output /tmp/buildkit.tar.gz \
    && echo "${BUILDKIT_SHA256}  /tmp/buildkit.tar.gz" | sha256sum --check - \
    && tar -xzf /tmp/buildkit.tar.gz -C /usr/local \
    && rm /tmp/buildkit.tar.gz
USER runner
