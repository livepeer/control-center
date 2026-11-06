.PHONY: api ui build test
api:
	cd api && go run ./cmd/controlcenter serve
ui:
	npm --prefix ui run dev
build:
	cd api && go build ./cmd/controlcenter
	npm --prefix ui run build
test:
	cd api && go test ./...
