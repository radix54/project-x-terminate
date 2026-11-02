.PHONY: run build clean

BIN_DIR		:=bin
APP_NAME	:=app
BIN			:=$(BIN_DIR)/$(APP_NAME)
#LIB_ARCHIVE := $(BIN_DIR)/*

ENGINE ?= $(if $(shell command -v podman),podman,docker)

# BINSEC reads an amd64 Linux binary, whatever machine you are on.
GOBUILD := CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath

# BINSEC runs in a container: no network, this folder mounted read-only at /work.
IMAGE := docker.io/binsec/binsec@sha256:2a51e455f055874d71cbf030a778e8be19455876bcd57c1845c163fed6fc482f
CONTAINER := $(ENGINE) run --rm --network=none --user root -v "$(CURDIR):/work:ro" -w /work \
	$(if $(filter podman,$(ENGINE)),--security-opt=label=disable) $(IMAGE)
# -checkct: constant-time check. Stop at the first leak; the limits keep each run short.
BINSEC := binsec -sse -checkct -checkct-leak-info halt -sse-depth 10000 -sse-timeout 120 -smt-timeout 5

run: build
	@./$(BIN)

build: #lib
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN) ./cmd

#lib: submodule
#	@mkdir -p $(BIN_DIR)
#	go build -buildmode=archive -o $(LIB_ARCHIVE) $(LIB_PKG)

# Development utilities
init: 
	@git config core.hooksPath .githooks

test:
	@go test -v ./mldsa44/kat_test.go

clean:
	@rm -rf $(BIN_DIR)

# make check on every configuration, then make line for each leak; one line per verdict.
# BINSEC prints a status even when it aborts on an error, so check for that too.
binsec: image
	@for config in binsec/*.ini; do \
		out=$$($(CONTAINER) $(BINSEC) -sse-script $$config -file build/target 2>&1); \
		status=$$(echo "$$out" | sed -n 's/.*Program status is : \([a-z]*\).*/\1/p'); \
		echo "$$out" | grep -q 'Fatal error' && status=error; \
		printf '%-30s %s\n' $$config "$${status:-error}"; \
		for addr in $$(echo "$$out" | grep -oE 'Instruction 0x[0-9a-f]+' | cut -d' ' -f2); do \
			echo "    leak at $$(echo $$addr | go tool addr2line build/target | sed -n '2s|^timinglab/||p')"; \
		done; \
	done

# Download the BINSEC image (600 MB) the first time.
image:
	@$(ENGINE) image inspect $(IMAGE) >/dev/null 2>&1 || $(ENGINE) pull $(IMAGE)

check: image
	$(CONTAINER) $(BINSEC) -sse-script $(CONFIG) -file build/target


