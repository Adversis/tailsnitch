VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_ID ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -X github.com/Adversis/tailsnitch/cmd.Version=$(VERSION) \
           -X github.com/Adversis/tailsnitch/cmd.BuildID=$(BUILD_ID) \
           -X github.com/Adversis/tailsnitch/cmd.BuildDate=$(BUILD_DATE)

.PHONY: build install clean rebuild

build:
	go build -ldflags "$(LDFLAGS)" -o tailsnitch .

rebuild: clean
	go build -a -ldflags "$(LDFLAGS)" -o tailsnitch .

install:
	go install -ldflags "$(LDFLAGS)" .

clean:
	rm -f tailsnitch
	go clean -cache
