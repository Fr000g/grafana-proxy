# Makefile for grafana-proxy multi-architecture builds

# Variables
BINARY_NAME := grafana-proxy
IMAGE_NAME := grafana-proxy
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
REGISTRY ?=
PLATFORMS := linux/amd64,linux/arm64

# Docker buildx builder name
BUILDER_NAME := multiarch-builder

# Targets
.PHONY: help build build-amd64 build-arm64 build-multi push push-amd64 push-arm64 push-multi clean binary setup-buildx

# Default target
all: build-multi

help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Setup Docker buildx for multi-platform builds
setup-buildx: ## Setup Docker buildx for multi-platform builds
	@docker buildx inspect $(BUILDER_NAME) >/dev/null 2>&1 || \
		docker buildx create --name $(BUILDER_NAME) --use --bootstrap
	@docker buildx use $(BUILDER_NAME)

# Build binary locally
binary: ## Build binary for current platform
	@echo "Building $(BINARY_NAME) binary..."
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME) .

# Build Docker image for amd64
build-amd64: setup-buildx ## Build Docker image for amd64
	@echo "Building $(IMAGE_NAME):$(VERSION)-amd64..."
	docker buildx build \
		--platform linux/amd64 \
		--build-arg VERSION=$(VERSION) \
		--tag $(IMAGE_NAME):$(VERSION)-amd64 \
		--tag $(IMAGE_NAME):latest-amd64 \
		--load \
		.

# Build Docker image for arm64
build-arm64: setup-buildx ## Build Docker image for arm64
	@echo "Building $(IMAGE_NAME):$(VERSION)-arm64..."
	docker buildx build \
		--platform linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		--tag $(IMAGE_NAME):$(VERSION)-arm64 \
		--tag $(IMAGE_NAME):latest-arm64 \
		--load \
		.

# Build both architectures
build: build-amd64 build-arm64 ## Build Docker images for both amd64 and arm64

# Build multi-platform image (requires registry for manifest)
build-multi: setup-buildx ## Build multi-platform Docker image
	@echo "Building multi-platform image $(IMAGE_NAME):$(VERSION)..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--tag $(IMAGE_NAME):$(VERSION) \
		--tag $(IMAGE_NAME):latest \
		.

# Push amd64 image to registry
push-amd64: build-amd64 ## Push amd64 image to registry
	@if [ -z "$(REGISTRY)" ]; then \
		echo "Error: REGISTRY variable is not set"; \
		echo "Usage: make push-amd64 REGISTRY=your-registry.com/username"; \
		exit 1; \
	fi
	@echo "Pushing $(REGISTRY)/$(IMAGE_NAME):$(VERSION)-amd64..."
	docker tag $(IMAGE_NAME):$(VERSION)-amd64 $(REGISTRY)/$(IMAGE_NAME):$(VERSION)-amd64
	docker tag $(IMAGE_NAME):latest-amd64 $(REGISTRY)/$(IMAGE_NAME):latest-amd64
	docker push $(REGISTRY)/$(IMAGE_NAME):$(VERSION)-amd64
	docker push $(REGISTRY)/$(IMAGE_NAME):latest-amd64

# Push arm64 image to registry
push-arm64: build-arm64 ## Push arm64 image to registry
	@if [ -z "$(REGISTRY)" ]; then \
		echo "Error: REGISTRY variable is not set"; \
		echo "Usage: make push-arm64 REGISTRY=your-registry.com/username"; \
		exit 1; \
	fi
	@echo "Pushing $(REGISTRY)/$(IMAGE_NAME):$(VERSION)-arm64..."
	docker tag $(IMAGE_NAME):$(VERSION)-arm64 $(REGISTRY)/$(IMAGE_NAME):$(VERSION)-arm64
	docker tag $(IMAGE_NAME):latest-arm64 $(REGISTRY)/$(IMAGE_NAME):latest-arm64
	docker push $(REGISTRY)/$(IMAGE_NAME):$(VERSION)-arm64
	docker push $(REGISTRY)/$(IMAGE_NAME):latest-arm64

# Push both architectures
push: push-amd64 push-arm64 ## Push both amd64 and arm64 images to registry

# Push multi-platform image to registry
push-multi: setup-buildx ## Push multi-platform image to registry
	@if [ -z "$(REGISTRY)" ]; then \
		echo "Error: REGISTRY variable is not set"; \
		echo "Usage: make push-multi REGISTRY=your-registry.com/username"; \
		exit 1; \
	fi
	@echo "Building and pushing multi-platform image $(REGISTRY)/$(IMAGE_NAME):$(VERSION)..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--tag $(REGISTRY)/$(IMAGE_NAME):$(VERSION) \
		--tag $(REGISTRY)/$(IMAGE_NAME):latest \
		--push \
		.

# Clean up
clean: ## Clean up built images and binaries
	@echo "Cleaning up..."
	-docker rmi $(IMAGE_NAME):$(VERSION)-amd64 2>/dev/null || true
	-docker rmi $(IMAGE_NAME):latest-amd64 2>/dev/null || true
	-docker rmi $(IMAGE_NAME):$(VERSION)-arm64 2>/dev/null || true
	-docker rmi $(IMAGE_NAME):latest-arm64 2>/dev/null || true
	-docker rmi $(IMAGE_NAME):$(VERSION) 2>/dev/null || true
	-docker rmi $(IMAGE_NAME):latest 2>/dev/null || true
	-rm -f $(BINARY_NAME)
	@echo "Cleanup complete."

# Clean buildx builder
clean-buildx: ## Remove buildx builder
	@echo "Removing buildx builder $(BUILDER_NAME)..."
	-docker buildx rm $(BUILDER_NAME)

# Development targets
dev-run: build-amd64 ## Run the application in development mode
	docker run --rm -it \
		-p 3000:3000 \
		-e USER=$(USER) \
		-e PASS=$(PASS) \
		-e BASEURL=$(BASEURL) \
		-e TOKEN=$(TOKEN) \
		$(IMAGE_NAME):$(VERSION)-amd64

# Show current version
version: ## Show current version
	@echo $(VERSION)

# Test build without pushing
test-build: setup-buildx ## Test build for all platforms without pushing
	@echo "Testing build for all platforms..."
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		.

# Show image sizes
image-sizes: ## Show sizes of built images
	@echo "Image sizes:"
	@docker images | grep $(IMAGE_NAME) | awk '{printf "%-50s %s\n", $$1":"$$2, $$7}'

# Publish (legacy compatibility)
publish: ## Legacy publish target
	curl -sSLo golang.sh https://raw.githubusercontent.com/Luzifer/github-publish/master/golang.sh
	bash golang.sh
