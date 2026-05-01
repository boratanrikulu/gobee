.PHONY: build test vet fmt clean install gen-helpers examples-translate examples-build examples-vet e2e ci-local

BIN := bin/gobee

build:
	go build -o $(BIN) ./cmd/gobee

test:
	go test -race ./...

vet:
	go vet ./...

# Translate every testdata/examples/*.go to a sibling .bpf.c via the
# gobee binary. Asserts the transpiler runs end-to-end (parse → validate
# → emit) on the full example matrix without errors. Output is
# discarded; the unit tests in internal/transpile own correctness, this
# target catches regressions in the CLI layer.
examples-translate: build
	@total=0; for src in testdata/examples/*.go; do \
		stem=$$(basename $$src .go); \
		tmpdir=$$(mktemp -d); \
		cp $$src $$tmpdir/$$stem.go; \
		$(BIN) translate -o $$tmpdir $$tmpdir > /dev/null 2>&1 || { echo "FAIL: $$src"; rm -rf $$tmpdir; exit 1; }; \
		rm -rf $$tmpdir; \
		total=$$((total+1)); \
	done; \
	echo "translated $$total examples"

# End-to-end build of the curated examples (helloworld + sysmon).
# Requires clang + llvm-strip + a Linux build env. Run inside lima.
examples-build: build
	$(MAKE) -C example/helloworld build
	$(MAKE) -C example/sysmon build

# Run bpfvet on the built .bpf.o for every curated example. Produces
# a portability report (min kernel, helpers, CO-RE relocations).
examples-vet: examples-build
	@which bpfvet > /dev/null || { echo "bpfvet not installed: go install github.com/boratanrikulu/bpfvet/cmd/bpfvet@v0.2.1"; exit 1; }
	@for o in $$(find example -name '*.bpf.o'); do \
		echo "==> $$o"; \
		bpfvet $$o || exit 1; \
	done

# Verifier acceptance: load every built .bpf.o into the running kernel
# and let the BPF verifier weigh in. Linux-only. Run inside lima after
# `make examples-build`.
e2e: examples-build
	go test -tags=integration ./e2e/...

# Local CI mirror — what GitHub Actions runs minus the Linux-only steps.
# Use `make ci-local` on macOS to catch most issues before pushing.
ci-local: vet test examples-translate
	@echo "ci-local: pass"

fmt:
	gofmt -w .
	goimports -w . 2>/dev/null || true

install:
	go install ./cmd/gobee

# Regenerate bpf/helpers_generated.go from the vendored bpf_helper_defs.h.
# Run after bumping tools/genhelpers/data/bpf_helper_defs.h. See SOURCE.md.
gen-helpers:
	go run ./tools/genhelpers > bpf/helpers_generated.go
	gofmt -w bpf/helpers_generated.go

clean:
	rm -rf bin/
	find . -name '*.bpf.o' -delete
