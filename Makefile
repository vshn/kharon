# Disable built-in rules
MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --no-builtin-variables
.SUFFIXES:
.SECONDARY:
.DEFAULT_GOAL := help

BIN_FILENAME ?= kharon

.PHONY: help
help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## Run tests
	go test ./... -coverprofile cover.out

.PHONY: build
build: generate ## Build binary
	go build -o $(BIN_FILENAME) .

.PHONY: generate
generate: ## Run go generate against code
	go generate ./...

.PHONY: fmt
fmt: ## Run go fmt against code
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code
	go vet ./...

.PHONY: lint
lint: fmt vet generate ## All-in-one linting
	@echo 'Check for uncommitted changes ...'
	git diff --exit-code

clean: ## Cleans up the generated resources
	rm -rf cover.out $(BIN_FILENAME) ||:

.PHONY: run
run: build ## Run a controller from your host.
	./$(BIN_FILENAME) domain_jumphost_mapping.json
