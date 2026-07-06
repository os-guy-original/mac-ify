# Mac-ify loader Makefile

CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11
LDFLAGS ?= -ldl -rdynamic

BIN_DIR  = ../build
BIN      = $(BIN_DIR)/macify

SRCS = main.c segments.c fixups.c runtime.c prefix.c \
       syscall/syscall_table.c syscall/syscall_names.c syscall/flag_translation.c \
       syscall/raw_syscall.c syscall/crash_handler.c syscall/sigill_handler.c syscall/patcher.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

%.o: %.c macify.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(BIN)
