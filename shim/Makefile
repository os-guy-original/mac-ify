# Mac-ify libSystem shim Makefile

CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11 -fPIC
LDFLAGS ?= -shared -lpthread -ldl -lm

BIN_DIR  = ../build
LIB      = $(BIN_DIR)/libmacify_shim.so

SRC = shim_core.c shim_mach.c shim_objc.c shim_tlv.c shim_pthread.c \
      shim_signal.c shim_io.c shim_misc.c shim_spawn.c
OBJ = $(SRC:.c=.o)

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -shared -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c shim.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -f $(LIB) $(OBJ)
