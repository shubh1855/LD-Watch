# LD-Watch Development Environment
# Base: Ubuntu 22.04 LTS
FROM ubuntu:22.04

# Avoid interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive

# ─── System Dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
  # C build tools (for audit library)
  gcc \
  make \
  # SQLite dev headers
  libsqlite3-dev \
  sqlite3 \
  # Debugging and inspection tools
  strace \
  ltrace \
  binutils \
  file \
  # General utilities
  git \
  curl \
  wget \
  vim \
  procps \
  # Clean up apt cache to keep image small
  && rm -rf /var/lib/apt/lists/*

# ─── Go Installation ───────────────────────────────────────────────────────────
ENV GO_VERSION=1.26.0
ENV GOPATH=/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

RUN curl -OL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
  tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
  rm go${GO_VERSION}.linux-amd64.tar.gz

# ─── Working Directory ─────────────────────────────────────────────────────────
WORKDIR /ld-watch

# ─── Copy project files ────────────────────────────────────────────────────────
COPY . .

# ─── Build everything ──────────────────────────────────────────────────────────
RUN make all

# ─── Runtime setup ─────────────────────────────────────────────────────────────
# Create directories needed at runtime
RUN mkdir -p /var/ldwatch /run

# Default command — drops into a bash shell
CMD ["/bin/bash"]
