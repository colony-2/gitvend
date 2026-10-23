.PHONY: build test check fuzz test-compose build-jobdb-provider check-jobdb-provider
build:
	go build -o bin/gitvend ./cmd/gitvend

test:
	go test -race ./...

check: test check-jobdb-provider
	go vet ./...

build-jobdb-provider:
	cd plugins/jobdb && go build -o ../../bin/jobdb-gitvend-secret-provider .

check-jobdb-provider:
	cd plugins/jobdb && go test -race ./...
	cd plugins/jobdb && go vet ./...

test-compose:
	python3 scripts/test-compose.py

fuzz:
	go test ./internal/policy -run '^$$' -fuzz FuzzCompile -fuzztime=15s -parallel=2
	go test ./internal/gitwire -run '^$$' -fuzz FuzzWire -fuzztime=15s -parallel=2
	go test ./internal/jsonutil -run '^$$' -fuzz FuzzDecode -fuzztime=15s -parallel=2
