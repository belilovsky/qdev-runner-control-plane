# syntax=docker/dockerfile:1.7
ARG RUNNER_VERSION=2.336.0
ARG RUNNER_SHA256=04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d

FROM ubuntu:24.04 AS base
ARG RUNNER_VERSION
ARG RUNNER_SHA256
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git git-lfs gnupg jq openssh-client python3 python3-pip \
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
    && /home/runner/actions-runner/bin/installdependencies.sh \
    && chown -R runner:runner /home/runner
COPY entrypoint.sh /usr/local/bin/qdev-runner-entrypoint
RUN chmod 0555 /usr/local/bin/qdev-runner-entrypoint
USER runner
WORKDIR /home/runner/actions-runner
ENTRYPOINT ["/usr/local/bin/qdev-runner-entrypoint"]

FROM base AS general

FROM mcr.microsoft.com/playwright:v1.55.0-noble AS browser
ARG RUNNER_VERSION
ARG RUNNER_SHA256
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git git-lfs jq openssh-client python3 python3-pip python3-venv \
      rsync unzip xz-utils zip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1001 --shell /bin/bash runner \
    && mkdir -p /home/runner/actions-runner \
    && curl --fail --location --retry 5 \
      "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
      --output /tmp/runner.tar.gz \
    && echo "${RUNNER_SHA256}  /tmp/runner.tar.gz" | sha256sum --check - \
    && tar -xzf /tmp/runner.tar.gz -C /home/runner/actions-runner \
    && rm /tmp/runner.tar.gz \
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
RUN curl --fail --location --retry 5 \
      "https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz" \
      --output /tmp/buildkit.tar.gz \
    && echo "${BUILDKIT_SHA256}  /tmp/buildkit.tar.gz" | sha256sum --check - \
    && tar -xzf /tmp/buildkit.tar.gz -C /usr/local \
    && rm /tmp/buildkit.tar.gz
USER runner
