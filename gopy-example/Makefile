PYTHON       ?= python3
GOPY         ?= gopy
GOIMPORTS    ?= goimports
OUTPUT_DIR   ?= protobomgo_py
GO_PACKAGE   ?= ./protobomgo/

GOPROXY      ?= https://proxy.golang.org,direct
export GOPROXY

.PHONY: all build clean deps run

all: build

# Install the Go tooling required by gopy.
deps:
	go install github.com/go-python/gopy@latest
	go install golang.org/x/tools/cmd/goimports@latest

# Build the Python extension module via gopy.
build:
	@echo "--- Tidying Go modules ---"
	go mod tidy
	@echo "--- Building gopy bindings ---"
	rm -rf $(OUTPUT_DIR)
	$(GOPY) build \
		-output=$(OUTPUT_DIR) \
		-vm=$(PYTHON) \
		-rename=true \
		$(GO_PACKAGE)
	@echo "--- Done. Extension module is in $(OUTPUT_DIR)/ ---"

# Run the example script.
run: build
	$(PYTHON) example.py

# Remove generated artifacts.
clean:
	rm -rf $(OUTPUT_DIR)
