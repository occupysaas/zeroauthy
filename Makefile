.PHONY: build test test-sql lint generate check-sources e2e conformance

build:
	CGO_ENABLED=0 go build -trimpath -o bin/zeroauthy ./cmd/zeroauthy
	CGO_ENABLED=0 go build -trimpath -o bin/zeroauthy-store-memory ./cmd/zeroauthy-store-memory

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

conformance:
	./tests/conformance/run.sh $(PLANS)
