# Mac-ify — top-level Makefile

.PHONY: all build test test-real binaries clean shim

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

clean:
	$(MAKE) -C src clean
	$(MAKE) -C shim clean
	rm -f tests/binaries/*.bin
	rm -f /tmp/macify-test.txt
