# Build and test ldap-cronin. Run `make help` for a list of targets.

BINARY     := ldap-cronin
PKG        := ./cmd/ldap-cronin
BIN_DIR    := bin
DIST_DIR   := dist
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS    := -s -w -X main.version=$(VERSION)

# -race needs cgo. The CI image (golang) ships gcc, so it works as is.
GO_TEST_FLAGS ?= -race -count=1

# OS/architecture pairs to cross-compile for distribution.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Lab images (Samba4 AD, OpenLDAP) to carry into an air-gapped environment. Set PLATFORM to the architecture of the
# destination docker host.
IMAGE        ?= ldap-cronin/samba-ad
LDAP_IMAGE   ?= ldap-cronin/openldap
IMAGE_TAG    ?= $(VERSION)
PLATFORM     ?= linux/amd64
# With EXCHANGE_ISO the Samba4 AD image carries Exchange's schema: its tag, and the bundle's name, end in -exchange.
AD_TAG       := $(IMAGE_TAG)$(if $(EXCHANGE_ISO),-exchange)
BUNDLE_NAME  := $(BINARY)-offline-$(VERSION)-$(subst /,-,$(PLATFORM))$(if $(EXCHANGE_ISO),-exchange)
BUNDLE_DIR   := $(DIST_DIR)/$(BUNDLE_NAME)
SHA256       := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo "shasum -a 256")

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this list
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the executable into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(PKG)

.PHONY: dist
dist: ## Build executables for each OS/architecture into dist/ for distribution
	@mkdir -p $(DIST_DIR)
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=""; [ "$$os" = windows ] && ext=".exe"; \
	  out="$(DIST_DIR)/$(BINARY)-$(VERSION)-$$os-$$arch$$ext"; \
	  echo "build $$out"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o "$$out" $(PKG) || exit 1; \
	done
	@cd $(DIST_DIR) && (sha256sum $(BINARY)-* 2>/dev/null || shasum -a 256 $(BINARY)-*) > SHA256SUMS

.PHONY: test
test: ## Run unit tests (-race)
	go test $(GO_TEST_FLAGS) ./...

.PHONY: cover
cover: ## Run unit tests with coverage and print a summary
	go test $(GO_TEST_FLAGS) -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

.PHONY: vet
vet: ## Run go vet (including the E2E code)
	go vet ./...
	go vet -tags e2e ./e2e

.PHONY: fmt
fmt: ## Format code with gofmt
	gofmt -w cmd internal e2e

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-formatted
	@out=$$(gofmt -l cmd internal e2e); \
	if [ -n "$$out" ]; then echo "files that need gofmt:"; echo "$$out"; echo "-> make fmt"; exit 1; fi

.PHONY: tidy-check
tidy-check: ## Fail if go.mod / go.sum differ from the result of go mod tidy
	@cp go.mod go.mod.bak; cp go.sum go.sum.bak; \
	go mod tidy; \
	if ! diff -q go.mod go.mod.bak >/dev/null || ! diff -q go.sum go.sum.bak >/dev/null; then \
	  mv go.mod.bak go.mod; mv go.sum.bak go.sum; \
	  echo "go.mod / go.sum do not match go mod tidy -> run go mod tidy and commit the result"; exit 1; \
	fi; \
	rm -f go.mod.bak go.sum.bak

.PHONY: check
check: fmt-check vet tidy-check test build ## Run the same checks as CI (format, vet, tidy, unit tests, build)

.PHONY: e2e
e2e: ## Start two Samba4 instances and run the E2E tests (requires docker; takes about 6 minutes)
	./tests/e2e.sh

.PHONY: e2e-binary
e2e-binary: ## Build the E2E test binary into bin/e2e.test (for running in environments without Go)
	CGO_ENABLED=0 go test -c -tags e2e -o $(BIN_DIR)/e2e.test ./e2e

.PHONY: up
up: ## Start the clone-target Samba4 AD (empty)
	docker compose up -d --build --wait

.PHONY: down
down: ## Stop the Samba4 AD and delete its volumes
	docker compose --profile e2e --profile ldap down -v

.PHONY: image
image: ## Build the lab images, Samba4 AD and OpenLDAP (PLATFORM=linux/arm64 for the architecture; EXCHANGE_ISO=<Exchange setup .iso> for a Samba4 AD with Exchange's schema)
ifeq ($(EXCHANGE_ISO),)
	docker build --platform $(PLATFORM) -t $(IMAGE):$(IMAGE_TAG) docker/ad
else
	@command -v bsdtar >/dev/null || { echo "bsdtar reads the ISO (macOS has it; Debian/Ubuntu: apt install libarchive-tools)"; exit 1; }
	rm -f docker/ad/exchange/*.ldf
	bsdtar -xf "$(EXCHANGE_ISO)" -C docker/ad/exchange --strip-components 2 'Setup/Data/PostWindows2003_schema*.ldf' 'Setup/Data/SchemaVersion.ldf'
	@# The schema files are Microsoft's: they are in the image only, and removed from the build context whatever happens.
	docker build --platform $(PLATFORM) -t $(IMAGE):$(AD_TAG) docker/ad; status=$$?; rm -f docker/ad/exchange/*.ldf; exit $$status
	@echo "$(IMAGE):$(AD_TAG) writes Exchange's schema to every lab it creates (lab up --image $(IMAGE):$(AD_TAG)). Do not publish it."
endif
	docker build --platform $(PLATFORM) -t $(LDAP_IMAGE):$(IMAGE_TAG) docker/ldap

.PHONY: bundle
bundle: image ## Build a tar.gz into dist/ to carry into an air-gapped environment (image, tool binaries, setup.sh; compose is not included). EXCHANGE_ISO=<iso>: its Samba4 AD has Exchange's schema
	rm -rf $(BUNDLE_DIR)
	mkdir -p $(BUNDLE_DIR)/images $(BUNDLE_DIR)/bin
	# One save for both images, so the Ubuntu layers they share are stored once.
	docker save $(IMAGE):$(AD_TAG) $(LDAP_IMAGE):$(IMAGE_TAG) -o $(BUNDLE_DIR)/images/lab.tar
	@for arch in amd64 arm64; do \
	  echo "build $(BUNDLE_DIR)/bin/$(BINARY)-linux-$$arch"; \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
	    -o $(BUNDLE_DIR)/bin/$(BINARY)-linux-$$arch $(PKG) || exit 1; \
	done
	printf 'ad=%s\nldap=%s\n' "$(IMAGE):$(AD_TAG)" "$(LDAP_IMAGE):$(IMAGE_TAG)" > $(BUNDLE_DIR)/IMAGE
	cp offline/setup.sh offline/README-OFFLINE.md config.example.toml README.md $(BUNDLE_DIR)/
	cp -r docs $(BUNDLE_DIR)/docs
	chmod +x $(BUNDLE_DIR)/setup.sh
	cd $(BUNDLE_DIR) && $(SHA256) images/lab.tar bin/* setup.sh IMAGE > SHA256SUMS
	tar -C $(DIST_DIR) -czf $(DIST_DIR)/$(BUNDLE_NAME).tar.gz $(BUNDLE_NAME)
	@echo
	@ls -lh $(DIST_DIR)/$(BUNDLE_NAME).tar.gz
	@echo "destination: tar xzf $(BUNDLE_NAME).tar.gz && cd $(BUNDLE_NAME) && ./setup.sh"
	$(if $(EXCHANGE_ISO),@echo "It holds Microsoft's Exchange schema files (in the image): carry it to your own environment only and never publish it.")

.PHONY: clean
clean: ## Remove generated files
	rm -rf $(BIN_DIR) $(DIST_DIR) coverage.out
