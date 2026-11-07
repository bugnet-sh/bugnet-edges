.PHONY: test lint build dev-certs

# The VPS's admin SSH, and where the dev wildcard pair lands on the Mac, outside every repository
VPS_SSH_PORT ?= 2222
DEV_CERTS_DIR ?= $(HOME)/.local/state/bugnet-dev/preview-dev
VPS_CERTS_DIR = /var/lib/bugnet-certs/preview-dev

test:
	go test -race ./...

lint:
	golangci-lint run ./...

build:
	go build ./...
	go build -o bin/x402-fake-seller ./cmd/x402-fake-seller

# Copies the dev wildcard pair from the VPS over the admin SSH, so the DNS token never leaves it
dev-certs:
	@test -n "$(VPS)" || { echo "usage: make dev-certs VPS=<user>@<host>" \
		"[VPS_SSH_PORT=<port>]" >&2; exit 2; }
	install -d -m 0700 "$(DEV_CERTS_DIR)"
	umask 077 && scp -q -P "$(VPS_SSH_PORT)" \
		"$(VPS):$(VPS_CERTS_DIR)/fullchain.pem" "$(VPS):$(VPS_CERTS_DIR)/key.pem" \
		"$(DEV_CERTS_DIR)/"
	chmod 0600 "$(DEV_CERTS_DIR)/fullchain.pem" "$(DEV_CERTS_DIR)/key.pem"
