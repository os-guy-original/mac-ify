# Mac-ify — top-level Makefile

PREFIX     ?= /usr/local
DESTDIR    ?=
BINDIR     := $(DESTDIR)$(PREFIX)/bin
LIBDIR     := $(DESTDIR)$(PREFIX)/lib/macify
SCRIPTSDIR := $(DESTDIR)$(PREFIX)/lib/macify/scripts

.PHONY: all build jail test test-smoke test-functional test-real asan clean shim shell install uninstall

jail:
	$(CC) $(CFLAGS) -o build/macify-jail src/jail.c

all: shim build binaries jail

shim:
	$(MAKE) -C shim

build:
	$(MAKE) -C src

binaries:
	python3 scripts/gen_macho.py

test: build binaries shim
	LD_LIBRARY_PATH=build python3 tests/run_tests.py

test-smoke: build shim
	@bash tests/real_smoke.sh

test-functional: build shim
	@bash tests/real_functional.sh

# Regression harness over tests/real binaries with per-binary expected
# output assertions (subset-based; skips missing binaries).
test-real: build shim
	@python3 tests/real_regression.py

# Sanitizer debug build: rebuilds everything with ASan+UBSan and -Werror.
# Run the result normally (LD_LIBRARY_PATH=build ./build/macify ...).
# `make clean && make` restores the optimized default build.
asan:
	$(MAKE) -C src clean
	$(MAKE) -C shim clean
	$(MAKE) -C src WERROR=-Werror SAN="-fsanitize=address,undefined -fno-omit-frame-pointer"
	$(MAKE) -C shim WERROR=-Werror SAN="-fsanitize=address,undefined -fno-omit-frame-pointer"
	$(MAKE) binaries

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
	install -m 755 scripts/macify $(BINDIR)/macify
	@for f in macify macify-shell macify-debug macify-init \
	          macify-setup-rootfs macify-setup-homebrew fetch_binaries.sh; do \
	    install -m 755 "scripts/$$f" "$(SCRIPTSDIR)/$$f"; \
	done
	@echo ""
	@echo "Installation complete:"
	@echo "  $(BINDIR)/macify — run macOS binaries (see: macify --help)"
	@echo ""
	@echo "First-time setup:"
	@echo "  macify init && macify doctor"

uninstall:
	@echo "Uninstalling macify from $(PREFIX)..."
	rm -f $(BINDIR)/macify
	rm -f $(BINDIR)/macify-shell
	rm -f $(BINDIR)/macify-debug
	rm -rf $(LIBDIR)
	@echo "Done."
