.PHONY: build test check fuzz test-compose build-jobdb-provider check-jobdb-provider
build: build-jobdb-provider
	go build -o bin/gitvend ./cmd/gitvend

test:
	go test -race ./...

check: test
	go vet ./...

build-jobdb-provider:
	go build -o bin/jobdb-gitvend-secret-provider ./cmd/jobdb-gitvend-secret-provider

check-jobdb-provider:
	go test -race ./pkg/jobdbprovider/... ./cmd/jobdb-gitvend-secret-provider/...
	go vet ./pkg/jobdbprovider/... ./cmd/jobdb-gitvend-secret-provider/...

test-compose:
	python3 scripts/test-compose.py

fuzz:
	go test ./internal/policy -run '^$$' -fuzz FuzzCompile -fuzztime=15s -parallel=2
	go test ./internal/gitwire -run '^$$' -fuzz FuzzWire -fuzztime=15s -parallel=2
	go test ./internal/jsonutil -run '^$$' -fuzz FuzzDecode -fuzztime=15s -parallel=2
