.PHONY: fmt test vet build check

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
	go build -o bin/wraith ./cmd/wraith

check: fmt test vet build
