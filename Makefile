.PHONY: dev generate lint build cli install-tools clean

# Like `next dev` — hot-reloading server
dev: generate
	@go run github.com/air-verse/air@latest

# Generate protobuf + connect code
generate:
	@buf lint
	@buf generate

# Lint protos
lint:
	@buf lint

# Build server and cli binaries
build: generate
	@go build -o bin/server ./cmd/server
	@go build -o bin/daocli ./cmd/daocli

# Run the CLI (pass ARGS, e.g. make cli ARGS="ping")
cli:
	@go run ./cmd/daocli $(ARGS)

# Install required tools
install-tools:
	@go install github.com/bufbuild/buf/cmd/buf@latest
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest
	@echo "tools installed — make sure \$$(go env GOPATH)/bin is in your PATH"

clean:
	@rm -rf bin tmp gen
