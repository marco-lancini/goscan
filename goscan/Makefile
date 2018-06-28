NAME := goscan
VERSION := 1.3
AUTHOR := Marco Lancini [@LanciniMarco]
LDFLAGS := -X 'main.version=$(VERSION)' -X 'main.author=$(AUTHOR)'

.DEFAULT_GOAL := help

.PHONY: setup
setup:  ## Setup for required tools.
	go get github.com/golang/lint/golint
	go get golang.org/x/tools/cmd/goimports
	go get -u github.com/golang/dep/cmd/dep
	dep ensure

.PHONY: fmt
fmt: ## Formatting source codes.
	go fmt ./...

.PHONY: lint
lint: ## Run golint and go vet.
	@golint ./core/...
	@go vet ./core/...

.PHONY: build
build: main.go  ## Build a binary.
	go build -ldflags "$(LDFLAGS)"

.PHONY: cross
cross: main.go  ## Build binaries for cross platform.
	mkdir -p pkg
	@for os in "darwin" "linux"; do \
		for arch in "amd64" "386"; do \
			GOOS=$${os} GOARCH=$${arch} make build; \
			zip pkg/goscan_$(VERSION)_$${os}_$${arch}.zip goscan; \
		done; \
	done

.PHONY: help
help: ## Show help text
	@echo "Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[36m%-20s\033[0m %s\n", $$1, $$2}'
