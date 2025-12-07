GOBIN ?= $$(go env GOPATH)/bin

.PHONY: install-go-test-coverage
install-go-test-coverage:
	go install github.com/vladopajic/go-test-coverage/v2@latest

.PHONY: check-coverage
check-coverage: install-go-test-coverage
	env -u GOCOVERDIR go test ./... -coverprofile=./cover.out -covermode=atomic -coverpkg=./...
	env -u GOCOVERDIR ${GOBIN}/go-test-coverage --config=./.testcoverage.yml

.PHONY: coverage-only
coverage-only:
	env -u GOCOVERDIR go test ./... -coverprofile=./cover.out -covermode=atomic -coverpkg=./...

clean:
	@echo "Cleaning up dist directory..."
	@rm -rf dist

build_snapshot:
	@echo "Building snapshot with GoReleaser..."
	@goreleaser release --snapshot --skip-publish --rm-dist