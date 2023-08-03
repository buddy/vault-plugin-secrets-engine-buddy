TOOL?=vault-plugin-secrets-engine-buddy
BUILD_TAGS?=${TOOL}
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)
BUDDY_GET_TOKEN?=curl
BUDDY_BASE_URL?=
BUDDY_INSECURE?=false

# bin generates releaseable binaries for this plugin
build: fmtcheck generate
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS)' sh -c "'$(CURDIR)/scripts/build.sh'"

default: build

test: fmtcheck generate
	$(eval BUDDY_TOKEN=$(shell sh -c "${BUDDY_GET_TOKEN}"))
	BUDDY_TOKEN=${BUDDY_TOKEN} BUDDY_INSECURE=${BUDDY_INSECURE} BUDDY_BASE_URL=${BUDDY_BASE_URL} sh -c "'$(CURDIR)/tests/run.sh'"

generate:
	go generate $(go list ./... | grep -v /vendor/)

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

fmt:
	gofmt -w $(GOFMT_FILES)

.PHONY: bin default generate test bootstrap fmt fmtcheck
