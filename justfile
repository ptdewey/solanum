run:
    @go run cmd/solanum/main.go

nix-run:
    @nix run .#default

test:
    @go test ./... -cover -coverprofile=cover.out
