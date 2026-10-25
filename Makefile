.PHONY: build test test-sql lint generate check-sources e2e e2e-deploy e2e-signing conformance console

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
	./scripts/check-sources.sh api/management.yaml

e2e:
	./tests/e2e/run-m3.sh
	./tests/e2e/run-browser.sh

e2e-deploy:
	./tests/e2e/run-m20-deploy.sh

e2e-signing:
	./tests/e2e/run-m20-signing.sh

conformance:
	./tests/conformance/run.sh $(PLANS)

# The admin console: install, lint, typecheck, test, regenerate the API
# types and rebuild console/dist (committed, embedded by go:embed).
console:
	cd console && npm ci --no-audit --no-fund
	cd console && npm run gen && npm run lint && npm run typecheck && npm test && npm run build
