# LD-Watch — Top-level Makefile

BINARY_DIR = bin
AUDIT_LIB  = audit/audit.so

.PHONY: all audit collector cli test clean docker-build docker-dev docker-ci help

## Default — build everything
all: $(BINARY_DIR) audit collector cli
	@echo ""
	@echo "✓ Build complete."
	@echo "  Audit library : $(AUDIT_LIB)"
	@echo "  Collector     : $(BINARY_DIR)/collector"
	@echo "  CLI           : $(BINARY_DIR)/ldwatch-cli"

## Create bin directory
$(BINARY_DIR):
	mkdir -p $(BINARY_DIR)

## Build the C audit library
audit:
	@echo "[make] Building audit library..."
	$(MAKE) -C audit
	@echo "[make] audit.so built."

## Build the Go collector daemon
collector: $(BINARY_DIR)
	@echo "[make] Building collector..."
	go build -o $(BINARY_DIR)/collector ./cmd/collector
	@echo "[make] collector built."

## Build the Go CLI
cli: $(BINARY_DIR)
	@echo "[make] Building ldwatch-cli..."
	go build -o $(BINARY_DIR)/ldwatch-cli ./cmd/ldwatch-cli
	@echo "[make] ldwatch-cli built."

## Run all tests
test:
	@echo "[make] Running all tests..."
	bash scripts/run_tests.sh

## Clean all build artifacts
clean:
	@echo "[make] Cleaning..."
	$(MAKE) -C audit clean
	rm -rf $(BINARY_DIR)/
	@echo "[make] Clean complete."

## Docker — build the image
docker-build:
	docker build -t ld-watch-dev ./docker

## Docker — drop into dev shell (with live repo mount)
docker-dev:
	docker compose run --rm dev

## Docker — simulate CI
docker-ci:
	docker compose run --rm ci

## Help
help:
	@echo ""
	@echo "LD-Watch — available make targets:"
	@echo ""
	@echo "  make all           Build everything (audit + collector + cli)"
	@echo "  make audit         Build C audit library only"
	@echo "  make collector     Build Go collector daemon only"
	@echo "  make cli           Build Go CLI only"
	@echo "  make test          Run all tests"
	@echo "  make clean         Remove all build artifacts"
	@echo "  make docker-build  Build Docker image"
	@echo "  make docker-dev    Open dev shell in Docker"
	@echo "  make docker-ci     Simulate CI run in Docker"
	@echo ""
