SHELL := /bin/sh

GO ?= go
GOFMT ?= gofmt
GITLEAKS_VERSION := v8.30.1
GOVULNCHECK_VERSION := v1.6.0
GITLEAKS := $(GO) run github.com/gitleaks/gitleaks/v8@$(GITLEAKS_VERSION)
GOVULNCHECK := $(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

.PHONY: all audit build check ci format format-check lint run \
	scan-secrets scan-secrets-history test test-integration test-unit

all: check

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/lafsecrets ./cmd/lafsecrets

run:
	$(GO) run ./cmd/lafsecrets

format:
	@files="$$(find . -type f -name '*.go' -not -path './.git/*')"; \
	if [ -n "$$files" ]; then $(GOFMT) -w $$files; fi

format-check:
	@files="$$(find . -type f -name '*.go' -not -path './.git/*')"; \
	unformatted="$$(if [ -n "$$files" ]; then $(GOFMT) -l $$files; fi)"; \
	if [ -n "$$unformatted" ]; then \
		printf '%s\n' "Go files require formatting:" "$$unformatted"; \
		exit 1; \
	fi

lint: format-check
	$(GO) vet ./...
	$(GO) vet -tags=integration ./...

test: test-unit test-integration

test-unit:
	$(GO) test -race -count=1 ./...

test-integration:
	$(GO) test -race -tags=integration -run '^TestIntegration' -count=1 ./...

audit:
	$(GO) mod verify
	$(GOVULNCHECK) -test ./...

scan-secrets:
	$(GITLEAKS) dir --redact --no-banner --no-color .

scan-secrets-history:
	@if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
		printf '%s\n' "secret history scan requires a Git worktree"; \
		exit 1; \
	fi
	git log --no-textconv --full-history --all --diff-filter=AM -p \
		--format= >/dev/null
	$(GITLEAKS) git --redact --no-banner --no-color \
		--log-opts="--no-textconv --full-history --all --diff-filter=AM" .

check: lint test audit scan-secrets

ci: check scan-secrets-history
