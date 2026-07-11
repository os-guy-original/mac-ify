# Mac-ify — top-level Makefile

PREFIX     ?= /usr/local
DESTDIR    ?=
BINDIR     := $(DESTDIR)$(PREFIX)/bin
LIBDIR     := $(DESTDIR)$(PREFIX)/lib/macify
SCRIPTSDIR := $(DESTDIR)$(PREFIX)/lib/macify/scripts

.PHONY: all build test test-real binaries clean shim shell install uninstall

all: shim build binaries

shim:
	$(MAKE) -C shim

build:
	$(MAKE) -C src

binaries:
	python3 scripts/gen_macho.py

test: build binaries shim
	LD_LIBRARY_PATH=build python3 tests/run_tests.py

test-real: build shim
	@bash scripts/test_real.sh

shell: build shim
	@bash scripts/macify-shell

clean:
	$(MAKE) -C src clean
	$(MAKE) -C shim clean
	rm -f tests/binaries/*.bin
	rm -f /tmp/macify-test.txt

# ── Install ─────────────────────────────────────────────────────
# Installs macify to PREFIX (default: /usr/local) so users can run
# `macify binary` and `macify-shell` from anywhere.
#
# Usage:
#   make install              # installs to /usr/local
#   make install PREFIX=~/.local  # installs to user directory
#   sudo make install         # system-wide install

install: build shim
	@echo "Installing macify to $(PREFIX)..."
	install -d $(BINDIR)
	install -d $(LIBDIR)
	install -d $(SCRIPTSDIR)
	install -m 755 build/macify $(LIBDIR)/macify
	install -m 755 build/libmacify_shim.so $(LIBDIR)/
	install -m 755 scripts/macify $(SCRIPTSDIR)/
	install -m 755 scripts/macify-shell $(SCRIPTSDIR)/
	install -m 755 scripts/macify-debug $(SCRIPTSDIR)/
	install -m 755 scripts/macify-init $(SCRIPTSDIR)/
	install -m 755 scripts/macify-setup-rootfs $(SCRIPTSDIR)/
	install -m 755 scripts/macify-setup-homebrew $(SCRIPTSDIR)/
	install -m 755 scripts/fetch_binaries.sh $(SCRIPTSDIR)/
	# Create wrapper script that sets LD_LIBRARY_PATH
	@echo '#!/bin/bash' > $(BINDIR)/macify
	@echo 'export LD_LIBRARY_PATH="$(LIBDIR):$$LD_LIBRARY_PATH"' >> $(BINDIR)/macify
	@echo 'exec "$(LIBDIR)/macify" "$$@"' >> $(BINDIR)/macify
	@chmod 755 $(BINDIR)/macify
	# Create macify-shell wrapper
	@echo '#!/bin/bash' > $(BINDIR)/macify-shell
	@echo 'export LD_LIBRARY_PATH="$(LIBDIR):$$LD_LIBRARY_PATH"' >> $(BINDIR)/macify-shell
	@echo 'export MACIFY_BINARY="$(LIBDIR)/macify"' >> $(BINDIR)/macify-shell
	@echo 'exec "$(SCRIPTSDIR)/macify-shell" "$$@"' >> $(BINDIR)/macify-shell
	@chmod 755 $(BINDIR)/macify-shell
	# Create macify-debug wrapper
	@echo '#!/bin/bash' > $(BINDIR)/macify-debug
	@echo 'export LD_LIBRARY_PATH="$(LIBDIR):$$LD_LIBRARY_PATH"' >> $(BINDIR)/macify-debug
	@echo 'export MACIFY_BINARY="$(LIBDIR)/macify"' >> $(BINDIR)/macify-debug
	@echo 'exec "$(SCRIPTSDIR)/macify-debug" "$$@"' >> $(BINDIR)/macify-debug
	@chmod 755 $(BINDIR)/macify-debug
	@echo ""
	@echo "Installation complete:"
	@echo "  $(BINDIR)/macify         — run macOS binaries"
	@echo "  $(BINDIR)/macify-shell   — interactive macOS bash shell"
	@echo "  $(BINDIR)/macify-debug   — debug tool for issue reports"
	@echo ""
	@echo "First-time setup:"
	@echo "  macify-shell 'echo hello'"

uninstall:
	@echo "Uninstalling macify from $(PREFIX)..."
	rm -f $(BINDIR)/macify
	rm -f $(BINDIR)/macify-shell
	rm -f $(BINDIR)/macify-debug
	rm -rf $(LIBDIR)
	@echo "Done."
