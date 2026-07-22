# LD-Watch Development Environment
# Base: Ubuntu 24.04 LTS
FROM ubuntu:24.04

# Avoid interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive

# Go configuration
ENV GO_VERSION=1.26.1
ENV GOPATH=/go
ENV PATH=/usr/local/go/bin:${GOPATH}/bin:${PATH}

# ──────────────────────────────────────────────────────────────────────────────
# System dependencies
# ──────────────────────────────────────────────────────────────────────────────
RUN apt-get update && \
  apt-get install -y \
  gcc \
  make \
  libsqlite3-dev \
  sqlite3 \
  strace \
  ltrace \
  binutils \
  file \
  git \
  curl \
  wget \
  vim \
  procps && \
  rm -rf /var/lib/apt/lists/*

# ──────────────────────────────────────────────────────────────────────────────
# Install Go
# ──────────────────────────────────────────────────────────────────────────────
RUN curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
  | tar -C /usr/local -xz

# ──────────────────────────────────────────────────────────────────────────────
# Working directory
# ──────────────────────────────────────────────────────────────────────────────
WORKDIR /ld-watch

# Runtime directories
RUN mkdir -p /var/ldwatch /run

# Default shell
CMD ["/bin/bash"]
