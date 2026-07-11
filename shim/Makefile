# Mac-ify libSystem shim Makefile

CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11 -fPIC
LDFLAGS ?= -shared -lpthread -ldl -lm -Wl,-z,now

BIN_DIR  = ../build
LIB      = $(BIN_DIR)/libmacify_shim.so

SRC = shim_core.c shim_mach.c shim_objc.c shim_tlv.c \
      shim_spawn.c \
      signal/init.c signal/crash_handler.c signal/sigaction.c \
      signal/sigset.c signal/sigmask.c signal/shim_symbol.c signal/go_signal.c \
      pthread/core.c pthread/stack.c pthread/tls.c pthread/sync.c \
      pthread/attr.c pthread/mutexattr.c pthread/create.c pthread/ssl_hooks.c \
      io/flags.c io/file.c io/net.c io/process.c io/dirent.c io/dl.c io/macos_stdio.c io/glob.c \
      misc/rune.c misc/cf.c misc/cf_compat.c misc/iokit.c misc/sysctl.c misc/string.c misc/unwind.c misc/objc_compat.c \
      sys/stubs.c sys/dispatch.c sys/random.c sys/kqueue.c sys/ucontext.c \
      sys/malloc.c sys/fs.c sys/mlock.c sys/misc_stubs.c

OBJ = $(SRC:.c=.o)

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -shared -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -f $(LIB) $(OBJ)
