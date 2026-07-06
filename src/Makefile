# Mac-ify loader Makefile

CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11
LDFLAGS ?= -ldl -rdynamic

BIN_DIR  = ../build
BIN      = $(BIN_DIR)/macify

SRCS = main.c segments.c syscall.c fixups.c runtime.c prefix.c
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
