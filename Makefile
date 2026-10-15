.PHONY: build test test-sql lint generate check-sources e2e

build:
	CGO_ENABLED=0 go build -trimpath -o bin/zeroauthy ./cmd/zeroauthy

test:
	go test ./...

test-sql:
	./scripts/test-sql.sh

lint:
	go vet ./...

generate:
	go generate ./...

check-sources:
	./scripts/check-sources.sh api/authentication.yaml

e2e:
	./tests/e2e/run-m3.sh
	./tests/e2e/run-browser.sh
