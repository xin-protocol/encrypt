.PHONY: build-node build-client build clean

build-node:
	@echo "Building Go Node..."
	cd node && go build -o ../node-bin

build-client:
	@echo "Building Go Client CLI..."
	cd client && go build -o ../client-bin

build: build-node build-client
	@echo "All binaries built successfully."

test:
	@echo "Running tests..."
	cd node && go test ./...
	cd client && go test ./...

fmt:
	@echo "Formatting Go code..."
	cd node && go fmt ./...
	cd client && go fmt ./...

clean:
	@echo "Cleaning up compiled binaries..."
	rm -f node-bin client-bin
	rm -f *.enc *.json *.txt
	rm -rf target/ contract/target/
	@echo "Clean complete."

REGISTRY ?= ghcr.io/teeyml
TAG ?= latest

docker-build:
	docker build -t $(REGISTRY)/soroban-encrypt-node:$(TAG) ./node
	docker build -t $(REGISTRY)/soroban-encrypt-client:$(TAG) ./client

docker-push:
	docker push $(REGISTRY)/soroban-encrypt-node:$(TAG)
	docker push $(REGISTRY)/soroban-encrypt-client:$(TAG)

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

build-versioned:
	cd node && go build $(LDFLAGS) -o node-bin/node .
	cd client && go build $(LDFLAGS) -o client-bin/client .
