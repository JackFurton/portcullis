GO ?= go
IMG ?= ghcr.io/jackfurton/portcullis:latest
GOLANGCI_VERSION ?= v2.6.2
LOCALBIN := $(CURDIR)/bin

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

##@ Development

.PHONY: build
build: ## Build every binary into bin/.
	$(GO) build -trimpath -o $(LOCALBIN)/ ./cmd/...

.PHONY: test
test: ## Run the unit tests.
	$(GO) test -race -coverprofile=cover.out ./...

.PHONY: cover
cover: test ## Show coverage per package.
	$(GO) tool cover -func=cover.out | tail -20

.PHONY: vet
vet: ## Run go vet.
	$(GO) vet ./...

$(LOCALBIN)/golangci-lint:
	GOBIN=$(LOCALBIN) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

.PHONY: lint
lint: $(LOCALBIN)/golangci-lint ## Run the linter.
	$(LOCALBIN)/golangci-lint run

.PHONY: check-policy
check-policy: ## Validate the demo policy. Point POLICY at your own to check it in CI.
	$(GO) run ./cmd/portcullis --check --policy=$(or $(POLICY),deploy/docker/policy.yaml)

##@ Image

.PHONY: image
image: ## Build the container image.
	docker build -t $(IMG) .

##@ Demo

.PHONY: demo-up
demo-up: ## Start Envoy, portcullis, a demo identity provider and an echo upstream.
	./hack/demo.sh up

.PHONY: demo-try
demo-try: ## Walk through the allow and deny cases.
	./hack/demo.sh try

.PHONY: demo-logs
demo-logs: ## Follow the decisions.
	./hack/demo.sh logs

.PHONY: demo-down
demo-down: ## Stop the demo stack.
	./hack/demo.sh down

.PHONY: smoke
smoke: ## Bring the stack up and assert every decision. This is what CI runs.
	./hack/smoke.sh
