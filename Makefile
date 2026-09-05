BINARY := icc
MODULE := github.com/instacryptio/ic-cli
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# -s -w strip the symbol table and DWARF debug info for smaller release binaries.
LDFLAGS := -ldflags "-s -w \
	-X '$(MODULE)/internal/cli.Version=$(VERSION)' \
	-X '$(MODULE)/internal/cli.CommitSHA=$(COMMIT)' \
	-X '$(MODULE)/internal/cli.BuildDate=$(DATE)'"

# Build tags. Defaults to fido2 (hardware-key/WebAuthn support), which needs
# libfido2 installed. On a machine without libfido2 (CI, etc.) build without it:
#   make build TAGS=
TAGS ?= fido2

# pkg-config binary. Overridable because some platforms ship only `pkgconf`
# (or a non-default path); cgo honors the same PKG_CONFIG env var, so exporting
# it keeps the libfido2 probe below and cgo's own pkg-config lookups in sync.
PKG_CONFIG ?= pkg-config

# If fido2 is requested but libfido2 isn't installed, warn and drop it rather
# than failing with a cryptic "fido.h: No such file or directory". pkg-config
# checks for the -dev package (headers); the runtime .so alone can't compile.
ifeq ($(filter fido2,$(TAGS)),fido2)
  ifneq ($(shell $(PKG_CONFIG) --exists libfido2 2>/dev/null && echo 1),1)
    $(warning libfido2 not found — building WITHOUT hardware-key (FIDO2) support.)
    $(warning   Install it to enable `icc settings cloud 2fa` hardware keys:)
    $(warning     Debian/Ubuntu: sudo apt install libfido2-dev)
    $(warning     Arch:          sudo pacman -S libfido2)
    $(warning     macOS:         brew install libfido2)
    TAGS := $(filter-out fido2,$(TAGS))
  endif
endif

ifeq ($(OS),Windows_NT)
  INSTALL_DIR  := $(subst \,/,$(LOCALAPPDATA))/Programs/icc
  INSTALL_BIN  := $(INSTALL_DIR)/$(BINARY).exe
  BUILD_BIN    := $(BINARY).exe
endif
ifneq ($(OS),Windows_NT)
  INSTALL_DIR  := $(HOME)/.local/bin
  INSTALL_BIN  := $(INSTALL_DIR)/$(BINARY)
  BUILD_BIN    := $(BINARY)
endif

.PHONY: build install uninstall clean test lint tidy

build:
	go build $(if $(TAGS),-tags "$(TAGS)") $(LDFLAGS) -o $(BUILD_BIN) ./cmd/icc/

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BUILD_BIN) $(INSTALL_BIN)
	@echo Installed to $(INSTALL_BIN)
ifeq ($(OS),Windows_NT)
	@powershell -Command "$$d='$(INSTALL_DIR)';$$p=[Environment]::GetEnvironmentVariable('Path','User');if($$p -notlike \"*$$d*\"){[Environment]::SetEnvironmentVariable('Path',\"$$p;$$d\",'User');Write-Host 'Added to user PATH (restart shell to take effect).'}"
endif

uninstall:
	rm -f $(INSTALL_BIN)
	@echo Uninstalled $(INSTALL_BIN)
ifeq ($(OS),Windows_NT)
	@powershell -Command "$$d='$(INSTALL_DIR)';$$p=[Environment]::GetEnvironmentVariable('Path','User');$$n=(($$p -split ';') | Where-Object {$$_ -ne $$d}) -join ';';[Environment]::SetEnvironmentVariable('Path',$$n,'User');Write-Host 'Removed from user PATH (restart shell to take effect).'"
endif

clean:
	rm -f $(BINARY)

test:
	cd ../icfx && go test ./...
	go test ./...

lint:
	cd ../icfx && golangci-lint run ./...
	golangci-lint run ./...

tidy:
	cd ../icfx && go mod tidy
	go mod tidy
