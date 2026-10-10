CC ?= cc
AR ?= ar
CFLAGS ?= -O2 -g
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?=
WARNFLAGS ?= -Wall -Wextra -Wpedantic -Wconversion
BUILD_DIR ?= build
NANOAMT_BUILD_POSIX ?= 1
SYSTEM ?= $(shell uname -s)
PROVE ?= prove
FUZZ_CC ?= clang
PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
DESTDIR ?=
INSTALL ?= install

CORE_SOURCES = lib/gateway.c lib/packet.c lib/igmp.c lib/reassembly.c
CORE_OBJECTS = $(CORE_SOURCES:%.c=$(BUILD_DIR)/%.o)
CORE_LIB = $(BUILD_DIR)/libnanoamt.a
POSIX_LIB = $(BUILD_DIR)/libnanoamt-posix.a
TEST_DIR = $(BUILD_DIR)/t/00util
TEST_BINS = $(TEST_DIR)/test-nanoamt $(TEST_DIR)/test-rfc
TARGETS = $(CORE_LIB)
ifeq ($(NANOAMT_BUILD_POSIX),1)
TARGETS += $(POSIX_LIB) $(BUILD_DIR)/nanoamt-recv
TEST_BINS += $(TEST_DIR)/test-posix
ifeq ($(SYSTEM),Linux)
TEST_BINS += $(TEST_DIR)/test-kernel
endif
endif
FUZZ_FLAGS = -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer
FUZZ_OBJECTS = $(CORE_SOURCES:%.c=$(BUILD_DIR)/fuzz/%.o) $(BUILD_DIR)/fuzz/fuzz/receive.o
OBJECTS = $(CORE_OBJECTS) $(BUILD_DIR)/lib/posix.o $(BUILD_DIR)/examples/recv.o \
          $(addprefix $(TEST_DIR)/,test_gateway.o test_rfc.o test_posix.o test_kernel.o) $(FUZZ_OBJECTS)

.PHONY: all check sanitize fuzz install clean indent
.DELETE_ON_ERROR:
all: $(TARGETS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) -Iinclude $(CFLAGS) -std=c99 $(NANOAMT_WARNFLAGS) -MMD -MP -c $< -o $@

$(CORE_OBJECTS) $(BUILD_DIR)/lib/posix.o: NANOAMT_WARNFLAGS = $(WARNFLAGS)

$(CORE_LIB): $(CORE_OBJECTS)
	rm -f $@
	$(AR) rcs $@ $^

$(POSIX_LIB): $(BUILD_DIR)/lib/posix.o
	rm -f $@
	$(AR) rcs $@ $^

$(BUILD_DIR)/nanoamt-recv: $(BUILD_DIR)/examples/recv.o $(POSIX_LIB) $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/test-nanoamt: $(TEST_DIR)/test_gateway.o $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/test-rfc: $(TEST_DIR)/test_rfc.o $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/test-posix $(TEST_DIR)/test-kernel: $(TEST_DIR)/test-%: $(TEST_DIR)/test_%.o $(POSIX_LIB) $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

check: all $(TEST_BINS)
	NANOAMT_BUILD_DIR="$(abspath $(BUILD_DIR))" NANOAMT_TEST_POSIX=$(NANOAMT_BUILD_POSIX) $(PROVE) -I. -v t/*.t

sanitize:
	$(MAKE) BUILD_DIR="$(BUILD_DIR)-sanitize" \
	    CFLAGS="$(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer" \
	    LDFLAGS="$(LDFLAGS) -fsanitize=address,undefined" check

$(BUILD_DIR)/fuzz/%.o: %.c
	@mkdir -p "$(@D)"
	$(FUZZ_CC) $(CPPFLAGS) -Iinclude $(CFLAGS) -std=c99 $(FUZZ_FLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/fuzz-nanoamt: $(FUZZ_OBJECTS)
	$(FUZZ_CC) $(CFLAGS) $(LDFLAGS) $(FUZZ_FLAGS) -o $@ $^ $(LDLIBS)

fuzz: $(BUILD_DIR)/fuzz-nanoamt

indent:
	clang-format -i include/*.h include/nanoamt/*.h lib/*.c lib/*.h examples/*.c fuzz/*.c t/00util/*.c t/00util/*.h

install: all
	$(INSTALL) -d "$(DESTDIR)$(LIBDIR)" "$(DESTDIR)$(INCLUDEDIR)"
	$(INSTALL) -m 644 $(CORE_LIB) "$(DESTDIR)$(LIBDIR)/libnanoamt.a"
	$(INSTALL) -m 644 include/nanoamt.h "$(DESTDIR)$(INCLUDEDIR)/nanoamt.h"
ifeq ($(NANOAMT_BUILD_POSIX),1)
	$(INSTALL) -d "$(DESTDIR)$(INCLUDEDIR)/nanoamt"
	$(INSTALL) -m 644 $(POSIX_LIB) "$(DESTDIR)$(LIBDIR)/libnanoamt-posix.a"
	$(INSTALL) -m 644 include/nanoamt/posix.h "$(DESTDIR)$(INCLUDEDIR)/nanoamt/posix.h"
endif

clean:
	rm -f $(OBJECTS) $(OBJECTS:.o=.d) $(CORE_LIB) $(POSIX_LIB) \
	    $(BUILD_DIR)/nanoamt-recv $(BUILD_DIR)/fuzz-nanoamt \
	    $(addprefix $(TEST_DIR)/,test-nanoamt test-rfc test-posix test-kernel)

-include $(OBJECTS:.o=.d)
