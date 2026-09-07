.PHONY: test vet race check

test:
	go test ./...

vet:
	go vet ./...

race:
	go test -race -coverprofile=coverage.out ./...

check: test vet race
