CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -Wshadow -Wformat=2 -Wconversion -fstack-protector-strong -O2 -D_FORTIFY_SOURCE=2 -fPIE -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -pthread
LDFLAGS ?= -pie -Wl,-z,relro,-z,now -pthread

GIT_VERSION := $(shell git describe --tags --always 2>/dev/null | sed 's/^v//')
VERSION ?= $(if $(GIT_VERSION),$(GIT_VERSION),0.0.0-unknown)
INCLUDES = -Iinclude

SRCDIR = src
TESTDIR = tests
BUILDDIR = build
BINDIR = bin

SOURCES = $(SRCDIR)/logger.c \
          $(SRCDIR)/crypto_utils.c \
          $(SRCDIR)/elf_analyzer.c \
          $(SRCDIR)/kernel_inspector.c \
          $(SRCDIR)/uefi_analyzer.c \
          $(SRCDIR)/mbr_auditor.c \
          $(SRCDIR)/initramfs_auditor.c \
          $(SRCDIR)/preload_scanner.c \
          $(SRCDIR)/pkg_integrity.c \
          $(SRCDIR)/ext4_diff.c \
          $(SRCDIR)/persistence_mgr.c \
          $(SRCDIR)/case_reporter.c \
          $(SRCDIR)/forensic_scan.c \
          $(SRCDIR)/disk_mount.c \
          $(SRCDIR)/rules_loader.c \
          $(SRCDIR)/firmware_auditor.c \
          $(SRCDIR)/tui/terminal.c \
          $(SRCDIR)/tui/wm.c \
          $(SRCDIR)/tui/pane.c \
          $(SRCDIR)/tui/tui_app.c

OBJECTS = $(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SOURCES))

TEST_SOURCES = $(wildcard $(TESTDIR)/*.c)
TEST_BINS = $(patsubst $(TESTDIR)/%.c, $(BUILDDIR)/%, $(TEST_SOURCES))

TARGET = $(BINDIR)/booto

.PHONY: all clean test run version iso dry-run asan fuzz coverage

all: version $(TARGET)

version: include/version.h

include/version.h: include/version.h.in scripts/gen_version.sh
	@scripts/gen_version.sh include/version.h.in include/version.h $(VERSION)

# asan/coverage builds reuse build/ with other flags: record the flags so a change rebuilds every object.
FLAGS_STAMP = $(BUILDDIR)/.flags
BUILD_FLAGS = $(CC) $(CFLAGS) $(LDFLAGS)
$(shell mkdir -p $(BUILDDIR) && echo '$(BUILD_FLAGS)' | cmp -s - $(FLAGS_STAMP) || echo '$(BUILD_FLAGS)' > $(FLAGS_STAMP))

$(BUILDDIR)/%.o: $(SRCDIR)/%.c include/version.h $(FLAGS_STAMP) | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): $(BUILDDIR)/main.o $(OBJECTS) | $(BINDIR)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

$(BUILDDIR)/main.o: $(SRCDIR)/main.c include/version.h $(FLAGS_STAMP) | $(BUILDDIR)
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BUILDDIR)/test_%: $(TESTDIR)/test_%.c $(OBJECTS) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJECTS) $(LDFLAGS) -o $@

test: version $(TEST_BINS)
	@echo "--- Running Test Suite ---"
	@for t in $(TEST_BINS); do \
		echo "Executing $$t..."; \
		$$t || exit 1; \
	done
	@echo "All tests passed successfully!"

asan: clean
	@echo "--- Compiling with AddressSanitizer & UndefinedBehaviorSanitizer ---"
	$(MAKE) CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -Werror -g -fsanitize=address,undefined -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -pthread" \
	        LDFLAGS="-fsanitize=address,undefined -pthread" test

fuzz: $(BUILDDIR)/test_fuzz
	@echo "--- Running Defensive Fuzzing Suite ---"
	$(BUILDDIR)/test_fuzz

# Bounded model checking (CBMC) of the parsers that read attacker-controlled bytes; see tests/cbmc/.
# PE: each buffer length is proved separately; the section loop bound is (len - 120) / 40 + 1 sections.
# GPT/MBR: a 1536-byte prefix with any sector size; the entry walk holds at most 12 entries.
# ELF: every 256-byte input (.modinfo walk stubbed), plus the .modinfo loop body on a 128-byte region.
CBMC ?= cbmc
GOTO_CC ?= goto-cc
GOTO_INSTRUMENT ?= goto-instrument
# 512 takes ~3 min; CBMC_LENGTHS="512 600" adds a ~18 min proof covering up to 12 sections.
CBMC_LENGTHS ?= 512
CBMC_FLAGS = --bounds-check --pointer-check --memory-leak-check --signed-overflow-check \
             --pointer-overflow-check --unwinding-assertions --object-bits 12 --slice-formula

cbmc: version | $(BUILDDIR)
	@for n in $(CBMC_LENGTHS); do \
		echo "--- CBMC: uefi_parse_pe_buffer on every $$n-byte input ---"; \
		$(CBMC) tests/cbmc/pe_authenticode_harness.c src/uefi_analyzer.c $(INCLUDES) -D_DEFAULT_SOURCE \
			-DPE_LEN=$$n --function harness $(CBMC_FLAGS) --unwind $$(( ($$n - 120) / 40 + 2 )) \
			--unwindset uefi_parse_pe_buffer.2:33 > $(BUILDDIR)/cbmc_$$n.log 2>&1; rc=$$?; \
		grep -E '^\*\*|VERIFICATION|FAILURE|Out of memory' $(BUILDDIR)/cbmc_$$n.log; \
		[ $$rc -eq 0 ] || exit 1; \
	done
	@echo "--- CBMC: disk_parse_esp_partitions on every 1536-byte prefix, any sector size ---"
	@$(CBMC) tests/cbmc/gpt_esp_harness.c src/disk_mount.c $(INCLUDES) -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L \
		--function harness $(CBMC_FLAGS) --unwind 13 --unwindset memcmp.0:17 > $(BUILDDIR)/cbmc_gpt.log 2>&1; rc=$$?; \
		grep -E '^\*\*|VERIFICATION|FAILURE|Out of memory' $(BUILDDIR)/cbmc_gpt.log; [ $$rc -eq 0 ]
	@echo "--- CBMC: elf_parse_buffer on every 256-byte input ---"
	@$(GOTO_CC) -o $(BUILDDIR)/cbmc_elf.goto tests/cbmc/elf_harness.c src/elf_analyzer.c $(INCLUDES) \
		-D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L --function harness && \
	$(GOTO_INSTRUMENT) --replace-calls elf_parse_modinfo:elf_parse_modinfo_stub \
		$(BUILDDIR)/cbmc_elf.goto $(BUILDDIR)/cbmc_elf_stubbed.goto > /dev/null && \
	$(CBMC) $(BUILDDIR)/cbmc_elf_stubbed.goto --function harness $(CBMC_FLAGS) --unwind 4 \
		--unwindset elf_parse_buffer.1:11,strcmp.0:65 > $(BUILDDIR)/cbmc_elf.log 2>&1; rc=$$?; \
		grep -E '^\*\*|VERIFICATION|FAILURE|Out of memory' $(BUILDDIR)/cbmc_elf.log; [ $$rc -eq 0 ]
	@echo "--- CBMC: elf_modinfo_entry (.modinfo loop body) on every 128-byte region ---"
	@$(CBMC) tests/cbmc/modinfo_harness.c src/elf_analyzer.c $(INCLUDES) -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L \
		--function harness $(CBMC_FLAGS) --unwind 2 --unwindset strncmp.0:13,nul_before_end.0:129 \
		> $(BUILDDIR)/cbmc_modinfo.log 2>&1; rc=$$?; \
		grep -E '^\*\*|VERIFICATION|FAILURE|Out of memory' $(BUILDDIR)/cbmc_modinfo.log; [ $$rc -eq 0 ]

coverage: clean
	@echo "--- Compiling with gcov Code Coverage Profiling ---"
	$(MAKE) CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -g -O0 --coverage -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -pthread" \
	        LDFLAGS="--coverage -pthread" test
	@./scripts/check_coverage.sh

run: all
	./$(TARGET)

dry-run: all
	./$(TARGET) --dry-run -V

iso: all
	sudo ./scripts/build_iso.sh

clean:
	rm -rf $(BUILDDIR) $(BINDIR) include/version.h *.gcda *.gcno
