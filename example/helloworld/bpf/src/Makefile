# BPF build — same pattern as gecit/pkg/ebpf/bpf/Makefile.
# Compiles counter.bpf.c (gobee output) into per-arch .bpf.o under bin/.
# Requires: clang with BPF target, llvm-strip.

CFLAGS := -Wall -Werror -O2 -g

BPF_DIR := .
OUTPUT_DIR_X86 := $(BPF_DIR)/../bin/x86
OUTPUT_DIR_ARM := $(BPF_DIR)/../bin/arm64

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPF_TARGET := bpfel

# On Debian/Ubuntu, asm/types.h lives under the multiarch include path
# instead of /usr/include/asm. Add it to the include search path so
# `#include <linux/bpf.h>` resolves regardless of host arch.
HOST_ARCH := $(shell uname -m)
MULTIARCH_INCLUDE := /usr/include/$(HOST_ARCH)-linux-gnu

BPF_CFLAGS := $(CFLAGS) -target $(BPF_TARGET) -I$(MULTIARCH_INCLUDE)

ENTRYPOINT_SRC := $(BPF_DIR)/counter.bpf.c

OUTPUTS_X86 := $(OUTPUT_DIR_X86)/counter.bpf.o
OUTPUTS_ARM := $(OUTPUT_DIR_ARM)/counter.bpf.o
OUTPUTS := $(OUTPUTS_X86) $(OUTPUTS_ARM)

.PHONY: bpf-all bpf-clean

bpf-all: $(OUTPUTS)

$(OUTPUT_DIR_X86)/counter.bpf.o: $(ENTRYPOINT_SRC)
	@mkdir -p $(OUTPUT_DIR_X86)
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_x86 -c $< -o $@
	$(LLVM_STRIP) -g $@

$(OUTPUT_DIR_ARM)/counter.bpf.o: $(ENTRYPOINT_SRC)
	@mkdir -p $(OUTPUT_DIR_ARM)
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_arm64 -c $< -o $@
	$(LLVM_STRIP) -g $@

bpf-clean:
	@rm -f $(OUTPUTS)
