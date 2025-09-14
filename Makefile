.PHONY: run test fmt tidy


run:
	go run ./cmd/cedar-authz


test:
	go test ./...


fmt:
	gofmt -s -w .


tidy:
	go mod tidy