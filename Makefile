.PHONY: api ui build test test-runtime
export REMOTE REF
api:
	cd api && go run ./cmd/controlcenter serve
ui:
	npm --prefix ui run dev
build:
	go build -o api/controlcenter ./api/cmd/controlcenter
	npm --prefix ui run build
test:
	go test ./...
	python3 -m unittest discover -s tools/tests -v
test-runtime:
	python3 tools/test-runtime-remote.py
