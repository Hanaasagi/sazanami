SHELL := /bin/bash

.DEFAULT_GOAL := help

.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: test
test: ## Run tests
	@cargo test

fmt: ## Format code
	@cargo fmt

# build-dev: ## Build for dev
# 	@cargo run --package xtask build-ebpf --features log
# 	@cargo build

# build-release: ## Build for release
# 	@cargo run --package xtask build-ebpf --release
# 	@cargo build --release

# run-dev: build-dev ## Run for dev
# 	@cargo xtask run

# run-release: build-release ## Run for release
# 	@cargo xtask run --release

run:
	@cargo build
	@RUST_BACKTRACE=1 RUST_LOG=none,sazanami=info cargo xtask run -- --config dev.yaml
