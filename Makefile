BIN      := flashsign
PKG      := ./...
CMD      := ./cmd/flashsign

.PHONY: all build install test race cover bench vet fmt fmt-check lint tidy clean help

all: build

## build: compile the flashsign CLI into ./flashsign
build:
	go build -o $(BIN) $(CMD)

## install: install the CLI into GOBIN
install:
	go install $(CMD)

## test: run the full test suite
test:
	go test $(PKG)

## race: run tests with the race detector
race:
	go test -race $(PKG)

## cover: run tests with coverage and open the report
cover:
	go test -coverprofile=coverage.out $(PKG)
	go tool cover -html=coverage.out

## bench: run benchmarks (see BENCHMARKS.md for methodology)
bench:
	go test -bench=. -benchmem -run=^$$ $(PKG)

## vet: run go vet
vet:
	go vet $(PKG)

## fmt: gofmt all source files in place
fmt:
	gofmt -w .

## fmt-check: fail if any file is not gofmt-formatted
fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

## lint: run staticcheck if installed (go install honnef.co/go/tools/cmd/staticcheck@latest)
lint:
	@command -v staticcheck >/dev/null 2>&1 && staticcheck $(PKG) || echo "staticcheck not installed; skipping"

## tidy: sync go.mod/go.sum
tidy:
	go mod tidy

## clean: remove build artifacts
clean:
	rm -f $(BIN) coverage.out

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
