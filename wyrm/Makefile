# wyrm - a WPA3 and WPA2 wireless security auditor
#
# The project has no third-party dependencies, so a plain Go toolchain is
# all that is required.

GO      ?= go
BIN     ?= bin/wyrm
PREFIX  ?= /usr/local
PKG     := github.com/darkLabz001/darksec-recon-suite/wyrm
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

GOFLAGS ?=

.DEFAULT_GOAL := all

.PHONY: all
all: lint test build ## Run the linters, the tests and build the binary

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the binary into ./bin
	@mkdir -p $(dir $(BIN))
	$(GO) build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/wyrm
	@echo "built $(BIN)"

.PHONY: install
install: build ## Install the binary into $(PREFIX)/bin
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 $(BIN) "$(DESTDIR)$(PREFIX)/bin/wyrm"
	@echo "installed $(DESTDIR)$(PREFIX)/bin/wyrm"

.PHONY: uninstall
uninstall: ## Remove the installed binary
	rm -f "$(DESTDIR)$(PREFIX)/bin/wyrm"

.PHONY: install-desktop
install-desktop: ## Install the desktop launcher and icon for the GUI
	install -d "$(HOME)/.local/share/applications" "$(HOME)/.local/share/icons/hicolor/scalable/apps"
	install -m 0644 contrib/wyrm.desktop "$(HOME)/.local/share/applications/wyrm.desktop"
	install -m 0644 contrib/wyrm.svg "$(HOME)/.local/share/icons/hicolor/scalable/apps/wyrm.svg"
	@echo "desktop launcher installed (restart the desktop shell to see it)"

.PHONY: test
test: ## Run the test suite
	$(GO) test ./...

.PHONY: race
race: ## Run the test suite under the race detector
	$(GO) test -race ./...

.PHONY: cover
cover: ## Run the test suite and write a coverage profile
	$(GO) test -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -func=coverage.out | tail -1
	@echo "coverage profile written to coverage.out"

.PHONY: lint
lint: ## Check formatting and run go vet
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "gofmt found unformatted files:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Format the source tree
	gofmt -w .

.PHONY: clean
clean: ## Remove build artefacts
	rm -rf bin coverage.out

.PHONY: tidy
tidy: ## Tidy the module file
	$(GO) mod tidy
