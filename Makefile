GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo none)
DATE ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
BINARY := bin/wraith
RELEASE_BINARY := bin/wraith-$(GOOS)-$(GOARCH)
LDFLAGS := -X github.com/Adam-Ghanem/Wraith/internal/buildinfo.Version=$(VERSION) -X github.com/Adam-Ghanem/Wraith/internal/buildinfo.Commit=$(COMMIT) -X github.com/Adam-Ghanem/Wraith/internal/buildinfo.Date=$(DATE)

.PHONY: fmt test vet lint build release sha256sums check

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

build:
	mkdir -p bin
	go build -o $(BINARY) ./cmd/wraith

release:
	mkdir -p bin
	go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(RELEASE_BINARY) ./cmd/wraith

sha256sums:
	sha256sum bin/wraith-* > SHA256SUMS

check: fmt test vet build
