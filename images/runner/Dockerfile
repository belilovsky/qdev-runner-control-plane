# syntax=docker/dockerfile:1.7
ARG RUNNER_VERSION=2.337.0
ARG RUNNER_SHA256=70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613
ARG NPM_VERSION=11.19.1
ARG NPM_SHA512=cedb312b1b7f92421a02cfb68b4194e88f8346651dacd6acc5364a25ef5309d4a32b19616a1ff8aff865e7280c0fa5c0835a99f5cd93368991e2a80ec9da75d2

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
FROM mcr.microsoft.com/playwright@sha256:c091b21d9fae78c76e85cd4356431e9b018402f172a214fc7d7a5e9a7e29d8ac AS browser
ARG RUNNER_VERSION
ARG RUNNER_SHA256
ARG NPM_VERSION
ARG NPM_SHA512
COPY install-pinned-npm.sh /usr/local/bin/install-pinned-npm
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
