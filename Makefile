.PHONY: build test check fuzz
build:
	go build -o bin/gitvend ./cmd/gitvend

test:
	go test -race ./...

check: test
	go vet ./...

fuzz:
	go test ./internal/policy -run '^$$' -fuzz FuzzCompile -fuzztime=15s -parallel=2
	go test ./internal/gitwire -run '^$$' -fuzz FuzzWire -fuzztime=15s -parallel=2
	go test ./internal/jsonutil -run '^$$' -fuzz FuzzDecode -fuzztime=15s -parallel=2
