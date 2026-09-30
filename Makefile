.PHONY: test vet race check contract

test:
	go test ./...

vet:
	go vet ./...

race:
	go test -race -coverprofile=coverage.out ./...

# 使用相邻 auth-server 仓库的当前 OpenAPI 核对全部在范围内的操作。
contract:
	AUTH_OPENAPI_SPEC=../auth-server/docs/openapi-v1.json go test -run '^TestOpenAPIContract$$' .

check: test vet race
