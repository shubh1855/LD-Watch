#!/bin/bash
# LD-Watch — Development Environment Setup
# Supports Ubuntu 22.04 and 24.04
# Run once on a fresh machine: bash scripts/setup.sh

set -e # exit on any error

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[setup]${NC} $1"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $1"; }
fail() {
  echo -e "${RED}[fail]${NC}  $1"
  exit 1
}

# ─── Check OS ─────────────────────────────────────────────────────────────────
log "Checking OS..."
if [ ! -f /etc/os-release ]; then
  fail "Cannot detect OS. This script supports Ubuntu 22.04 and 24.04 only."
fi
source /etc/os-release
if [[ "$ID" != "ubuntu" ]]; then
  fail "This script is for Ubuntu only. Got: $ID"
fi
log "Detected: Ubuntu $VERSION_ID"

# ─── System packages ──────────────────────────────────────────────────────────
log "Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y \
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
  wget

log "System packages installed."

# ─── Go ───────────────────────────────────────────────────────────────────────
GO_VERSION="1.26.1"
GO_INSTALL_DIR="/usr/local"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"

INSTALL_GO=false

if command -v go &>/dev/null; then
  INSTALLED_GO=$(go version | awk '{print $3}' | sed 's/go//')
  if [ "$INSTALLED_GO" = "$GO_VERSION" ]; then
    log "Go ${GO_VERSION} already installed."
  else
    warn "Go ${INSTALLED_GO} detected. Upgrading to ${GO_VERSION}..."
    INSTALL_GO=true
  fi
else
  log "Go not found. Installing Go ${GO_VERSION}..."
  INSTALL_GO=true
fi

if [ "$INSTALL_GO" = true ]; then
  curl -fLO "https://go.dev/dl/${GO_TARBALL}"
  curl -fsSLO "https://go.dev/dl/${GO_TARBALL}.sha256"
  echo "$(cat "${GO_TARBALL}.sha256")  ${GO_TARBALL}" | sha256sum -c -

  GO_STAGING_DIR="$(mktemp -d)"
  if ! tar -C "$GO_STAGING_DIR" -xzf "$GO_TARBALL" || \
    [ ! -x "$GO_STAGING_DIR/go/bin/go" ]; then
    rm -rf -- "$GO_STAGING_DIR" "$GO_TARBALL" "${GO_TARBALL}.sha256"
    fail "Downloaded Go archive could not be staged. Existing Go installation was left unchanged."
  fi

  sudo rm -rf "${GO_INSTALL_DIR}/go"
  sudo mv "$GO_STAGING_DIR/go" "${GO_INSTALL_DIR}/go"
  rm -rf -- "$GO_STAGING_DIR"
  rm "$GO_TARBALL" "${GO_TARBALL}.sha256"

  SHELL_RC="$HOME/.bashrc"
  if [ -n "$ZSH_VERSION" ]; then
    SHELL_RC="$HOME/.zshrc"
  fi

  if ! grep -q "/usr/local/go/bin" "$SHELL_RC"; then
    {
      echo 'export PATH=$PATH:/usr/local/go/bin'
      echo 'export GOPATH=$HOME/go'
      echo 'export PATH=$PATH:$GOPATH/bin'
    } >>"$SHELL_RC"
  fi

  export PATH="/usr/local/go/bin:$PATH"

  log "Go ${GO_VERSION} installed."
fi

# ─── Go module setup ──────────────────────────────────────────────────────────
log "Setting up Go module..."
if [ ! -f go.mod ]; then
  go mod init github.com/your-org/ld-watch
  log "go.mod created."
else
  log "go.mod already exists, running go mod tidy..."
  go mod tidy
fi

# ─── Runtime directories ──────────────────────────────────────────────────────
log "Creating runtime directories..."
sudo mkdir -p /var/ldwatch
sudo mkdir -p /run
sudo chown "$USER":"$USER" /var/ldwatch

# ─── Verify everything ────────────────────────────────────────────────────────
log "Verifying installation..."

command -v gcc &>/dev/null && log "gcc:   OK" || fail "gcc not found"
command -v make &>/dev/null && log "make:  OK" || fail "make not found"
command -v go &>/dev/null && log "go:    OK ($(go version))" || fail "go not found"
command -v sqlite3 &>/dev/null && log "sqlite3: OK" || fail "sqlite3 not found"

echo ""
log "Setup complete. Run 'make all' to build the project."
