# Basic make.
# Exists here to explain common commands to help in the development.

CARGO = cargo
RUSTUP = rustup
CROSS = $$HOME/.cargo/bin/cross
DOCKER = docker
PROFILE_DATA = llvm-profdata
PROFILE_COV = llvm-cov
JQ = jq
GREP = grep
TEE = tee

# Intentionally not in the release target list: Darwin.  That requires extra tool chain
# installation for non-linux installs that require extra effort not here.
# This assumes building from a Linux platform.
RELEASE_TARGETS ?= x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu x86_64-pc-windows-gnu
CARGO_ZIGBUILD = $(CARGO) zigbuild
ZIG_TARGETS = $(filter %-linux-gnu %-linux-musl,$(RELEASE_TARGETS))
NATIVE_TARGETS = $(filter-out $(ZIG_TARGETS),$(RELEASE_TARGETS))


## dev                  Standard developer execution tasks.
.PHONY: dev
dev: build-debug fmt lint test doc build-lib

## build-debug          Build the debug-enabled executable for the current architecture/OS.
.PHONY: build-debug
build-debug:

.PHONY: build-debug-cmd
build-debug: build-debug-cmd
build-debug-cmd:
	$(CARGO) build

# extensions build for WASM, which isn't a "current" architecture/OS.
.PHONY: build-debug-guest-kit
build-debug: build-debug-guest-kit
build-debug-guest-kit:
	$(RUSTUP) target add wasm32-wasip1
	cd extensions/guest-kit && $(CARGO) build --target wasm32-wasip1

.PHONY: build-debug-nodejs-releases
build-debug: build-debug-nodejs-releases
build-debug-nodejs-releases:
	cd extensions/nodejs-releases && $(CARGO) build --target wasm32-wasip1

.PHONY: build-debug-corretto-releases
build-debug: build-debug-corretto-releases
build-debug-corretto-releases:
	cd extensions/corretto-releases && $(CARGO) build --target wasm32-wasip1


## build-debug-arm64    Build the debug executable for the Linux glib+ARM64 platform.
.PHONY: build-debug-arm64
build-debug-arm64:
	$(RUSTUP) target add --toolchain aarch64-unknown-linux-gnu
	$(CROSS) build --target aarch64-unknown-linux-gnu


## build-release        Build the release executable for the current architecture/OS.
.PHONY: build-release
build-release:

.PHONY: build-release-cmd
build-release: build-release-cmd
build-release-cmd:
	$(CARGO) build --release

.PHONY: build-release-extensions
build-release-extensions:

.PHONY: build-release-guest-kit
build-release: build-release-guest-kit
build-release-guest-kit:
	$(RUSTUP) target add wasm32-wasip1
	cd extensions/guest-kit && $(CARGO) build --target wasm32-wasip1 --release

.PHONY: build-release-nodejs-releases
build-release: build-release-nodejs-releases
build-release-extensions: build-release-nodejs-releases
build-release-nodejs-releases: build-release-guest-kit
	cd extensions/nodejs-releases && $(CARGO) build --target wasm32-wasip1 --release

.PHONY: build-release-corretto-releases
build-release: build-release-corretto-releases
build-release-extensions: build-release-corretto-releases
build-release-corretto-releases: build-release-guest-kit
	cd extensions/corretto-releases && $(CARGO) build --target wasm32-wasip1 --release


## build-lib            Build only the library for the current architecture/OS, skipping the executable.
.PHONY: build-lib
build-lib:
	$(CARGO) build --lib


## build-all-release    Build all the targets (not cross-platform).
.PHONY: build-all-release
build-all-release:
	$(CARGO) build --release --all-targets


## build-cross-release  Build the release executable for every platform in RELEASE_TARGETS,
##                      without Docker/cross.  Output lands in target/<triple>/release/.
##                      Linux targets use cargo-zigbuild for the C deps (aws-lc, ring, sqlite).
##                      Windows uses the mingw-w64 toolchain (x86_64-w64-mingw32-gcc).
##                      macOS is not included: it needs the Apple SDK, so build it on a Mac.
##                      Override the list:  make build-cross-release RELEASE_TARGETS="..."
.PHONY: build-cross-release
build-cross-release:
	$(RUSTUP) target add $(RELEASE_TARGETS)
ifneq ($(strip $(ZIG_TARGETS)),)
	$(CARGO_ZIGBUILD) --release --bins $(foreach t,$(ZIG_TARGETS),--target $(t))
endif
ifneq ($(strip $(NATIVE_TARGETS)),)
	$(CARGO) build --release --bins $(foreach t,$(NATIVE_TARGETS),--target $(t))
endif


## installer            Build the installer for the current architecture/OS.
.PHONY: installer
installer: build-release
	./build-scripts/mk-installer.sh current


## installer-cross      Build the installer for each target.
.PHONY: installer-cross
installer-cross: build-cross-release build-release-extensions installer
	./build-scripts/mk-installer.sh $(RELEASE_TARGETS)


## build-arm64-release  Build the release executable for the Linux glib+ARM64 platform.
.PHONY: build-arm64-release
build-arm64-release:
	$$HOME/.cargo/bin/cross build --target aarch64-unknown-linux-gnu --release


## test                 Run the test suite.  Offline; never contacts a registry.
.PHONY: test
test:

.PHONY: test-cmd
test: test-cmd
test-cmd:
	$(CARGO) test --lib

.PHONY: test-guest-kit
test: test-guest-kit
test-guest-kit:
	cd extensions/guest-kit && $(CARGO) test --lib

.PHONY: test-nodejs-releases
test: test-nodejs-releases
test-nodejs-releases:
	cd extensions/nodejs-releases && $(CARGO) test --lib

.PHONY: test-corretto-releases
test: test-corretto-releases
test-corretto-releases:
	cd extensions/corretto-releases && $(CARGO) test --lib


## test-examples        A simple test to make sure the examples are still valid.
.PHONY: test-examples
test-examples:
	NEXUS_TOKEN=x LEGACY_SIGNING_KEY=y \
		$(CARGO) run --quiet -- validate-config --config examples/configuration/config.yaml


## lint                 Check for common mistakes.
.PHONY: lint
lint:

.PHONY: lint-cmd
lint: lint-cmd
lint-cmd:
	$(CARGO) clippy --all-targets -- -D warnings

.PHONY: lint-guest-kit
lint: lint-guest-kit
lint-guest-kit:
	cd extensions/guest-kit && $(CARGO) clippy --all-targets -- -D warnings

.PHONY: lint-nodejs-releases
lint: lint-nodejs-releases
lint-nodejs-releases:
	cd extensions/nodejs-releases && $(CARGO) clippy --all-targets -- -D warnings

.PHONY: lint-corretto-releases
lint: lint-corretto-releases
lint-corretto-releases:
	cd extensions/corretto-releases && $(CARGO) clippy --all-targets -- -D warnings


## fmt-check            Report formatting problems without changing any file.
.PHONY: fmt-check
fmt-check:

.PHONY: fmt-check-cmd
fmt-check: fmt-check-cmd
fmt-check-cmd:
	$(CARGO) fmt --check
	$(CARGO) clippy --lib --all-targets

.PHONY: fmt-check-guest-kit
fmt-check: fmt-check-guest-kit
fmt-check-guest-kit:
	cd extensions/guest-kit && $(CARGO) fmt --check
	cd extensions/guest-kit && $(CARGO) clippy --lib --all-targets

.PHONY: fmt-check-nodejs-releases
fmt-check: fmt-check-nodejs-releases
fmt-check-nodejs-releases:
	cd extensions/nodejs-releases && $(CARGO) fmt --check
	cd extensions/nodejs-releases && $(CARGO) clippy --lib --all-targets

.PHONY: fmt-check-corretto-releases
fmt-check: fmt-check-corretto-releases
fmt-check-corretto-releases:
	cd extensions/corretto-releases && $(CARGO) fmt --check
	cd extensions/corretto-releases && $(CARGO) clippy --lib --all-targets


## check                Everything CI runs: formatting, lints, and tests.
.PHONY: check
check: fmt-check lint test test-examples


## test-coverage  Run unit tests with coverage reports.
##                This requires first installing the llvm-cov:
##                   cargo install cargo-llvm-cov
.PHONY: test-coverage
test-coverage:
	$(CARGO) llvm-cov clean --workspace
	$(CARGO) llvm-cov --no-report
	$(CARGO) llvm-cov report --lcov --output-path target/lcov.info
	$(CARGO) llvm-cov report --codecov --output-path target/codecov.json
	$(CARGO) llvm-cov report --html --output-dir target/coverage/

## fmt            Update the source code to conform to standard formatting rules.
.PHONY: fmt
fmt:

.PHONY: fmt-cmd
fmt: fmt-cmd
fmt-cmd:
	$(CARGO) fmt --all

.PHONY: fmt-guest-kit
fmt: fmt-guest-kit
fmt-guest-kit:
	cd extensions/guest-kit && $(CARGO) fmt --all

.PHONY: fmt-nodejs-releases
fmt: fmt-nodejs-releases
fmt-nodejs-releases:
	cd extensions/nodejs-releases && $(CARGO) fmt --all

.PHONY: fmt-corretto-releases
fmt: fmt-corretto-releases
fmt-corretto-releases:
	cd extensions/corretto-releases && $(CARGO) fmt --all

## doc            Create documentation from the source.
.PHONY: doc
doc:
	$(CARGO) doc --no-deps

## all-doc        Create documentation from the source, even the dependencies.
.PHONY: all-doc
all-doc:
	$(CARGO) doc

## clean          Clean up constructed files.
.PHONY: clean
clean:
	-rm -r target
	-rm -r extensions/guest-kit/target
	-rm -r extensions/nodejs-releases/target
	-rm -r extensions/corretto-releases/target


# Integration Test stuff
.PHONY: start-local-servers stop-local-servers
start-local-servers:
	./manual-integration-tests/setup/sctl.sh start all
	@echo "You should next run './manual-integration-tests/setup/nexus/accept-eula.sh' in a few minutes"
stop-local-servers:
	./manual-integration-tests/setup/sctl.sh stop all
	-$(DOCKER) volume rm artifact-copy-artifact-keeper_ak-postgres-data
	-$(DOCKER) volume rm artifact-copy-artifact-keeper_ak-storage
	-$(DOCKER) volume rm artifact-copy-artifactory_artifactory-data
	-$(DOCKER) volume rm artifact-copy-nexus_nexus-data
	-rm ./manual-integration-tests/setup/*/.env

.PHONY: publish-to-local-servers
publish-to-local-servers:
	./manual-integration-tests/tests/000-publish-maven-nexus.sh
	./manual-integration-tests/tests/001-publish-maven-artifactory.sh
	./manual-integration-tests/tests/002-publish-maven-ak.sh
	./manual-integration-tests/tests/010-publish-raw-nexus.sh
	./manual-integration-tests/tests/011-publish-raw-artifactory.sh
	./manual-integration-tests/tests/012-publish-raw-ak.sh
	./manual-integration-tests/tests/013-publish-ivy-artifactory.sh
	./manual-integration-tests/tests/020-publish-pypi-nexus.sh
	./manual-integration-tests/tests/021-publish-pypi-ak.sh
	./manual-integration-tests/tests/030-publish-npm-nexus.sh
	./manual-integration-tests/tests/031-publish-npm-ak.sh


## help           This screen.
.PHONY: help
help:
	@grep -E '^##' $(MAKEFILE_LIST) | cut -c 4-
