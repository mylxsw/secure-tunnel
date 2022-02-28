BIN := secure-tunnel
LDFLAGS := -s -w -X main.Version=$(shell date "+%Y%m%d%H%M") -X main.GitCommit=$(shell git rev-parse --short HEAD)

run-server: build-server
	./build/debug/$(BIN)-server | jq

run-client: build-client
	./build/debug/$(BIN)-client

build-server:
	go build -ldflags "$(LDFLAGS)" -o build/debug/$(BIN)-server cmd/server/main.go

build-client:
	go build -ldflags "$(LDFLAGS)" -o build/debug/$(BIN)-client cmd/client/main.go

build-release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o build/release/$(BIN)-server cmd/server/main.go
	CGO_ENABLED=0 GOOS=linux go build -ldflags "$(LDFLAGS)" -o build/release/$(BIN)-client-linux cmd/client/main.go
	CGO_ENABLED=0 GOOS=darwin go build -ldflags "$(LDFLAGS)" -o build/release/$(BIN)-client-darwin cmd/client/main.go
	CGO_ENABLED=0 GOOS=windows go build -ldflags "$(LDFLAGS)" -o build/release/$(BIN)-client.exe cmd/client/main.go

clean:
	rm -fr build/debug/ build/release/

.PHONY: run-server run-client build-server build-client build-release clean deploy
