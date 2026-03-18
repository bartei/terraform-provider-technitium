default: build

build:
	go build -v ./...

test:
	go test -v ./... -count=1

testacc:
	TF_ACC=1 go test -v ./... -count=1 -timeout 120m

testacc-up:
	@test -f .env.test || (echo "ERROR: .env.test not found. Copy .env.test.example to .env.test and fill in values." && exit 1)
	docker compose -f docker-compose.test.yml up -d --wait
	$(MAKE) testacc

testacc-down:
	docker compose -f docker-compose.test.yml down -v

generate:
	go generate ./...
	go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate

lint:
	golangci-lint run ./...

install:
	go build -o ~/.terraform.d/plugins/registry.terraform.io/darkhonor/technitium/0.0.1/$$(go env GOOS)_$$(go env GOARCH)/terraform-provider-technitium

.PHONY: build test testacc testacc-up testacc-down generate lint install
