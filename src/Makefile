# Mac-ify loader Makefile

CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-format-truncation -Wno-stringop-truncation -std=gnu11
LDFLAGS ?= -ldl -rdynamic

# Optional strictness/sanitizer knobs (compose with CFLAGS):
#   make WERROR=-Werror
#   make SAN="-fsanitize=address,undefined -fno-omit-frame-pointer"
WERROR ?=
SAN    ?=
CFLAGS += $(WERROR) $(SAN)
LDFLAGS += $(SAN)

BIN_DIR  = ../build
BIN      = $(BIN_DIR)/macify

SRCS = main.c segments.c fixups.c runtime.c prefix.c macho_dylib.c watchdog.c \
       syscall/syscall_table.c syscall/syscall_names.c syscall/flag_translation.c \
       syscall/raw_syscall.c syscall/crash_handler.c syscall/sigill_handler.c syscall/patcher.c
OBJDIR  = ../build/obj/src
OBJS    = $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(OBJDIR)/%.o: %.c macify.h | $(OBJDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(OBJDIR) $(BIN)
