# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM debian:bookworm-slim

ARG TARGETOS
ARG TARGETARCH

# Install dependencies for downloading binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Versions
ARG KUBE_VERSION=v1.35.0
ARG ETCD_VERSION=v3.6.7

# Download kube-apiserver
RUN curl -L "https://dl.k8s.io/release/${KUBE_VERSION}/bin/${TARGETOS}/${TARGETARCH}/kube-apiserver" -o /usr/local/bin/kube-apiserver \
    && chmod +x /usr/local/bin/kube-apiserver

# Download etcd
RUN curl -L "https://github.com/etcd-io/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-${TARGETOS}-${TARGETARCH}.tar.gz" -o etcd.tar.gz \
    && tar xzvf etcd.tar.gz \
    && mv etcd-${ETCD_VERSION}-${TARGETOS}-${TARGETARCH}/etcd /usr/local/bin/ \
    && mv etcd-${ETCD_VERSION}-${TARGETOS}-${TARGETARCH}/etcdctl /usr/local/bin/ \
    && rm -rf etcd.tar.gz etcd-${ETCD_VERSION}-${TARGETOS}-${TARGETARCH}

# Setup directories
RUN mkdir -p /var/run/etcd /data/etcd

# Copy entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Expose ports (kube-apiserver default secure port is 6443)
EXPOSE 6443

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
