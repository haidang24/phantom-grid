CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror

# Go dependencies
GO_MOD := go.mod

all: generate build

generate:
	go generate ./...

build: generate
	go build -o phantom-grid cmd/agent/main.go
	go build -o spa-client cmd/spa-client/main.go

run: build
	sudo ./phantom-grid

clean:
	rm -f phantom-grid spa-client
	rm -f cmd/agent/phantom_bpf*
	rm -f cmd/agent/egress_bpf*

deps:
	go mod tidy


