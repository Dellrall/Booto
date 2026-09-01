CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -Wshadow -Wformat=2 -Wconversion -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now

VERSION ?= 0.3.0-beta
INCLUDES = -Iinclude

SRCDIR = src
TESTDIR = tests
BUILDDIR = build
BINDIR = bin

SOURCES = $(SRCDIR)/logger.c \
          $(SRCDIR)/crypto_utils.c \
          $(SRCDIR)/elf_analyzer.c \
          $(SRCDIR)/kernel_inspector.c \
          $(SRCDIR)/disk_mount.c \
          $(SRCDIR)/tui/terminal.c \
          $(SRCDIR)/tui/wm.c \
          $(SRCDIR)/tui/pane.c \
          $(SRCDIR)/tui/tui_app.c

OBJECTS = $(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SOURCES))

TEST_SOURCES = $(wildcard $(TESTDIR)/*.c)
TEST_BINS = $(patsubst $(TESTDIR)/%.c, $(BUILDDIR)/%, $(TEST_SOURCES))

TARGET = $(BINDIR)/booto

.PHONY: all clean test run version iso dry-run

all: version $(TARGET)

version: include/version.h

include/version.h: include/version.h.in scripts/gen_version.sh
	@scripts/gen_version.sh include/version.h.in include/version.h $(VERSION)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c include/version.h | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): $(BUILDDIR)/main.o $(OBJECTS) | $(BINDIR)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

$(BUILDDIR)/main.o: $(SRCDIR)/main.c include/version.h | $(BUILDDIR)
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

run: all
	./$(TARGET)

dry-run: all
	./$(TARGET) --dry-run -V

iso: all
	sudo ./scripts/build_iso.sh

clean:
	rm -rf $(BUILDDIR) $(BINDIR) include/version.h
