CC ?= cc
AR ?= ar
CFLAGS ?= -O2 -g
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?=
WARNFLAGS ?= -Wall -Wextra -Wpedantic -Wconversion
BUILD_DIR ?= build
NANOAMT_BUILD_POSIX ?= 1
NANOAMT_BUILD_AMTQ ?= 1
NANOAMT_BUILD_OPENSSL ?= 0
SYSTEM ?= $(shell uname -s)
PROVE ?= prove
FUZZ_CC ?= clang
PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
DESTDIR ?=
INSTALL ?= install

CORE_SOURCES = lib/gateway.c lib/packet.c lib/igmp.c lib/reassembly.c lib/membership.c lib/relay.c
CORE_OBJECTS = $(CORE_SOURCES:%.c=$(BUILD_DIR)/%.o)
CORE_LIB = $(BUILD_DIR)/libnanoamt.a
AMTQ_SOURCES = lib/amtq/wire.c lib/amtq/control.c lib/amtq/gateway.c lib/amtq/relay.c lib/amtq/reassembly.c
AMTQ_OBJECTS = $(AMTQ_SOURCES:%.c=$(BUILD_DIR)/%.o)
AMTQ_LIB = $(BUILD_DIR)/libnanoamt-amtq.a
POSIX_LIB = $(BUILD_DIR)/libnanoamt-posix.a
OPENSSL_LIB = $(BUILD_DIR)/libnanoamt-openssl.a
TEST_DIR = $(BUILD_DIR)/t/00util
TEST_BINS = $(TEST_DIR)/test-nanoamt $(TEST_DIR)/test-rfc $(TEST_DIR)/test-membership $(TEST_DIR)/test-relay
TARGETS = $(CORE_LIB)
ifeq ($(NANOAMT_BUILD_OPENSSL),1)
TARGETS += $(OPENSSL_LIB)
TEST_BINS += $(TEST_DIR)/test-openssl
endif
ifeq ($(NANOAMT_BUILD_AMTQ),1)
TARGETS += $(AMTQ_LIB)
TEST_BINS += $(TEST_DIR)/test-amtq $(TEST_DIR)/test-amtq-relay
endif
ifeq ($(NANOAMT_BUILD_POSIX),1)
TARGETS += $(POSIX_LIB) $(BUILD_DIR)/nanoamt-recv
TEST_BINS += $(TEST_DIR)/test-posix
ifeq ($(SYSTEM),Linux)
TEST_BINS += $(TEST_DIR)/test-kernel $(TEST_DIR)/test-relay-posix
endif
endif
FUZZ_FLAGS = -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer
FUZZ_OBJECTS = $(CORE_SOURCES:%.c=$(BUILD_DIR)/fuzz/%.o) $(BUILD_DIR)/fuzz/fuzz/receive.o
AMTQ_FUZZ_OBJECTS = $(AMTQ_SOURCES:%.c=$(BUILD_DIR)/fuzz/%.o) $(BUILD_DIR)/fuzz/fuzz/amtq.o
AMTQ_RELAY_FUZZ_OBJECTS = $(AMTQ_SOURCES:%.c=$(BUILD_DIR)/fuzz/%.o) $(BUILD_DIR)/fuzz/fuzz/amtq_relay.o
RELAY_FUZZ_OBJECTS = $(CORE_SOURCES:%.c=$(BUILD_DIR)/fuzz/%.o) $(BUILD_DIR)/fuzz/fuzz/relay.o
OBJECTS = $(CORE_OBJECTS) $(AMTQ_OBJECTS) $(BUILD_DIR)/lib/posix.o $(BUILD_DIR)/lib/relay_posix.o $(BUILD_DIR)/lib/openssl.o $(BUILD_DIR)/examples/recv.o \
          $(addprefix $(TEST_DIR)/,test_gateway.o test_rfc.o test_membership.o test_relay.o test_openssl.o test_posix.o test_relay_posix.o test_kernel.o test_amtq.o test_amtq_relay.o) $(FUZZ_OBJECTS) $(AMTQ_FUZZ_OBJECTS) $(AMTQ_RELAY_FUZZ_OBJECTS) $(RELAY_FUZZ_OBJECTS)

.PHONY: all check sanitize fuzz fuzz-amtq fuzz-amtq-relay fuzz-relay install clean indent
.DELETE_ON_ERROR:
all: $(TARGETS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) -Iinclude $(CFLAGS) -std=c99 $(NANOAMT_WARNFLAGS) -MMD -MP -c $< -o $@

$(CORE_OBJECTS) $(AMTQ_OBJECTS) $(BUILD_DIR)/lib/posix.o $(BUILD_DIR)/lib/relay_posix.o $(BUILD_DIR)/lib/openssl.o: NANOAMT_WARNFLAGS = $(WARNFLAGS)

$(CORE_LIB): $(CORE_OBJECTS)
	rm -f $@
	$(AR) rcs $@ $^

$(POSIX_LIB): $(BUILD_DIR)/lib/posix.o $(BUILD_DIR)/lib/relay_posix.o
	rm -f $@
	$(AR) rcs $@ $^

$(OPENSSL_LIB): $(BUILD_DIR)/lib/openssl.o
	rm -f $@
	$(AR) rcs $@ $^

$(AMTQ_LIB): $(AMTQ_OBJECTS)
	rm -f $@
	$(AR) rcs $@ $^

$(TEST_DIR)/test-amtq: $(TEST_DIR)/test_amtq.o $(AMTQ_LIB) $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/test-amtq-relay: $(TEST_DIR)/test_amtq_relay.o $(AMTQ_LIB) $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/nanoamt-recv: $(BUILD_DIR)/examples/recv.o $(POSIX_LIB) $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/test-nanoamt: $(TEST_DIR)/test_gateway.o $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/test-rfc: $(TEST_DIR)/test_rfc.o $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/test-membership: $(TEST_DIR)/test_membership.o $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/test-relay: $(TEST_DIR)/test_relay.o $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/test-openssl: $(TEST_DIR)/test_openssl.o $(OPENSSL_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS) -lcrypto

$(TEST_DIR)/test-posix $(TEST_DIR)/test-kernel: $(TEST_DIR)/test-%: $(TEST_DIR)/test_%.o $(POSIX_LIB) $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_DIR)/test-relay-posix: $(TEST_DIR)/test_relay_posix.o $(POSIX_LIB) $(CORE_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

check: all $(TEST_BINS)
	NANOAMT_BUILD_DIR="$(abspath $(BUILD_DIR))" NANOAMT_TEST_POSIX=$(NANOAMT_BUILD_POSIX) NANOAMT_TEST_AMTQ=$(NANOAMT_BUILD_AMTQ) NANOAMT_TEST_OPENSSL=$(NANOAMT_BUILD_OPENSSL) $(PROVE) -I. -v t/*.t

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

$(BUILD_DIR)/fuzz-amtq: $(AMTQ_FUZZ_OBJECTS) $(CORE_SOURCES:%.c=$(BUILD_DIR)/fuzz/%.o)
	$(FUZZ_CC) $(CFLAGS) $(LDFLAGS) $(FUZZ_FLAGS) -o $@ $^ $(LDLIBS)

fuzz-amtq: $(BUILD_DIR)/fuzz-amtq

$(BUILD_DIR)/fuzz-amtq-relay: $(AMTQ_RELAY_FUZZ_OBJECTS) $(CORE_SOURCES:%.c=$(BUILD_DIR)/fuzz/%.o)
	$(FUZZ_CC) $(CFLAGS) $(LDFLAGS) $(FUZZ_FLAGS) -o $@ $^ $(LDLIBS)

fuzz-amtq-relay: $(BUILD_DIR)/fuzz-amtq-relay

$(BUILD_DIR)/fuzz-relay: $(RELAY_FUZZ_OBJECTS)
	$(FUZZ_CC) $(CFLAGS) $(LDFLAGS) $(FUZZ_FLAGS) -o $@ $^

fuzz-relay: $(BUILD_DIR)/fuzz-relay

indent:
	clang-format -i include/*.h include/nanoamt/*.h lib/*.c lib/*.h lib/amtq/*.c lib/amtq/*.h examples/*.c fuzz/*.c t/00util/*.c t/00util/*.h

install: all
	$(INSTALL) -d "$(DESTDIR)$(LIBDIR)" "$(DESTDIR)$(INCLUDEDIR)"
	$(INSTALL) -m 644 $(CORE_LIB) "$(DESTDIR)$(LIBDIR)/libnanoamt.a"
	$(INSTALL) -m 644 include/nanoamt.h "$(DESTDIR)$(INCLUDEDIR)/nanoamt.h"
	$(INSTALL) -d "$(DESTDIR)$(INCLUDEDIR)/nanoamt"
	$(INSTALL) -m 644 include/nanoamt/membership.h "$(DESTDIR)$(INCLUDEDIR)/nanoamt/membership.h"
	$(INSTALL) -m 644 include/nanoamt/relay.h "$(DESTDIR)$(INCLUDEDIR)/nanoamt/relay.h"
ifeq ($(NANOAMT_BUILD_OPENSSL),1)
	$(INSTALL) -m 644 $(OPENSSL_LIB) "$(DESTDIR)$(LIBDIR)/libnanoamt-openssl.a"
	$(INSTALL) -m 644 include/nanoamt/openssl.h "$(DESTDIR)$(INCLUDEDIR)/nanoamt/openssl.h"
endif
ifeq ($(NANOAMT_BUILD_AMTQ),1)
	$(INSTALL) -d "$(DESTDIR)$(INCLUDEDIR)/nanoamt"
	$(INSTALL) -m 644 $(AMTQ_LIB) "$(DESTDIR)$(LIBDIR)/libnanoamt-amtq.a"
	$(INSTALL) -m 644 include/nanoamt/amtq.h "$(DESTDIR)$(INCLUDEDIR)/nanoamt/amtq.h"
	$(INSTALL) -m 644 include/nanoamt/amtq_relay.h "$(DESTDIR)$(INCLUDEDIR)/nanoamt/amtq_relay.h"
endif
ifeq ($(NANOAMT_BUILD_POSIX),1)
	$(INSTALL) -d "$(DESTDIR)$(INCLUDEDIR)/nanoamt"
	$(INSTALL) -m 644 $(POSIX_LIB) "$(DESTDIR)$(LIBDIR)/libnanoamt-posix.a"
	$(INSTALL) -m 644 include/nanoamt/posix.h "$(DESTDIR)$(INCLUDEDIR)/nanoamt/posix.h"
	$(INSTALL) -m 644 include/nanoamt/relay_posix.h "$(DESTDIR)$(INCLUDEDIR)/nanoamt/relay_posix.h"
endif

clean:
	rm -f $(OBJECTS) $(OBJECTS:.o=.d) $(CORE_LIB) $(POSIX_LIB) $(AMTQ_LIB) $(OPENSSL_LIB) \
    $(BUILD_DIR)/nanoamt-recv $(BUILD_DIR)/fuzz-nanoamt $(BUILD_DIR)/fuzz-amtq $(BUILD_DIR)/fuzz-amtq-relay $(BUILD_DIR)/fuzz-relay \
    $(addprefix $(TEST_DIR)/,test-nanoamt test-rfc test-membership test-relay test-openssl test-posix test-relay-posix test-kernel test-amtq test-amtq-relay)

-include $(OBJECTS:.o=.d)
