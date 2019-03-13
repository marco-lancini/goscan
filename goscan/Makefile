NAME := goscan
VERSION := 2.4
AUTHOR := Marco Lancini [@LanciniMarco]
LDFLAGS := -X 'main.version=$(VERSION)' -X 'main.author=$(AUTHOR)'

.DEFAULT_GOAL := help

.PHONY: init
init:  ## Init the project.
	go get -u github.com/golang/dep/cmd/dep
	dep init

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
	# # MAC 64
	# GOOS=darwin GOARCH=amd64 make build
	# zip pkg/goscan_$(VERSION)_darwin_amd64.zip goscan
	# LINUX 64
	GOOS=linux GOARCH=amd64 make build
	zip pkg/goscan_$(VERSION)_linux_amd64.zip goscan
	# LINUX 32
	CGO_ENABLED=1 CC="gcc -m32" GOOS=linux GOARCH=386 make build
	zip pkg/goscan_$(VERSION)_linux_386.zip goscan

.PHONY: help
help: ## Show help text
	@echo "Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[36m%-20s\033[0m %s\n", $$1, $$2}'
