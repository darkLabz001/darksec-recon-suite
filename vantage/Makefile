# vantage - a fast, precise port scanner
#
# The project has no third-party dependencies, so a plain Go toolchain is
# all that is required.

GO      ?= go
BIN     ?= bin/vantage
PKG     := github.com/darkLabz001/darksec-recon-suite/vantage
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
	$(GO) build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/vantage
	@echo "built $(BIN)"

.PHONY: install
install: ## Install the binary into $(DESTDIR)/usr/local/bin
	$(GO) install -trimpath -ldflags '$(LDFLAGS)' ./cmd/vantage

.PHONY: install-desktop
install-desktop: ## Install the desktop launcher and icon for the GUI
	install -d "$(HOME)/.local/share/applications" "$(HOME)/.local/share/icons/hicolor/scalable/apps"
	install -m 0644 contrib/vantage.desktop "$(HOME)/.local/share/applications/vantage.desktop"
	install -m 0644 contrib/vantage.svg "$(HOME)/.local/share/icons/hicolor/scalable/apps/vantage.svg"
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

.PHONY: bench
bench: ## Run the Go benchmarks
	$(GO) test -run '^$$' -bench . -benchmem ./...

.PHONY: bench-sweep
bench-sweep: build ## Measure the throughput of a loopback sweep
	@echo "full TCP range on one host"
	@$(MAKE) --no-print-directory sweep BENCH_ARGS="-p 1-65535" BENCH_TARGET=127.0.0.1
	@echo "top 1000 ports over a /24"
	@$(MAKE) --no-print-directory sweep BENCH_ARGS="--top-ports 1000" BENCH_TARGET=127.0.0.0/24

.PHONY: sweep
sweep: ## Run a single sweep and report the elapsed time
	@start=$$(date +%s%N); \
	./$(BIN) $(BENCH_ARGS) --quiet --no-color --format csv -o /dev/null $(BENCH_TARGET); \
	end=$$(date +%s%N); \
	echo "  $$(( (end - start) / 1000000 )) ms"

.PHONY: clean
clean: ## Remove build artefacts
	rm -rf bin coverage.out

.PHONY: tidy
tidy: ## Tidy the module file
	$(GO) mod tidy
