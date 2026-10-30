.PHONY: e2e-organizations-ii e2e-organizations build test test-sql lint generate check-sources e2e e2e-actions e2e-actions-ii e2e-rbac e2e-email-accounts e2e-social e2e-deploy e2e-signing e2e-email e2e-branding e2e-domains conformance console

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

e2e-actions:
	./tests/e2e/run-m27-actions.sh

e2e-organizations-ii:
	./tests/e2e/run-m30-organizations-ii.sh

e2e-organizations:
	./tests/e2e/run-m29-organizations.sh

e2e-rbac:
	./tests/e2e/run-m26-rbac.sh

e2e-email-accounts:
	./tests/e2e/run-m25-email-accounts.sh

e2e-social:
	./tests/e2e/run-m24-social.sh

e2e-deploy:
	./tests/e2e/run-m20-deploy.sh

e2e-signing:
	./tests/e2e/run-m20-signing.sh

e2e-email:
	./tests/e2e/run-m21-email.sh

e2e-branding:
	./tests/e2e/run-m22-branding.sh

e2e-domains:
	./tests/e2e/domains/run-acme.sh http01,tlsalpn,dns01
	./tests/e2e/run-m23-domains.sh

conformance:
	./tests/conformance/run.sh $(PLANS)

# The admin console: install, lint, typecheck, test, regenerate the API
# types and rebuild console/dist (committed, embedded by go:embed).
console:
	cd console && npm ci --no-audit --no-fund
	cd console && npm run gen && npm run lint && npm run typecheck && npm test && npm run build

e2e-actions-ii:
	./tests/e2e/run-m28-actions-ii.sh
