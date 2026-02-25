# AES-IGE-AEAD Library
# Build: make [static|shared|all]
# Test: make test

CC = gcc
AR = ar
CFLAGS = -Wall -Wextra -std=c99 -Iinclude -O2
LDFLAGS =

SRCS = src/sha256.c src/aes.c src/gf128.c src/aes_ige.c src/poly_mac.c src/aes_ige_aead.c \
       src/chacha20.c src/poly1305.c src/chacha20_poly1305.c
OBJS = $(SRCS:.c=.o)
LIB_STATIC = libaes_ige_aead.a
LIB_SHARED = libaes_ige_aead.so

.PHONY: all static shared clean test demo

all: static test

static: $(LIB_STATIC)

shared: $(LIB_SHARED)

$(LIB_STATIC): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	ranlib $@

$(LIB_SHARED): $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(LDFLAGS)

tests/test_vectors: $(OBJS) tests/test_vectors.c
	$(CC) $(CFLAGS) -o $@ $(OBJS) tests/test_vectors.c $(LDFLAGS)

demo/demo: $(OBJS) demo/demo.c
	$(CC) $(CFLAGS) -o $@ $(OBJS) demo/demo.c $(LDFLAGS)

test: tests/test_vectors
	./tests/test_vectors

demo: demo/demo
	./demo/demo

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(LIB_STATIC) $(LIB_SHARED) tests/test_vectors demo/demo

install: static
	install -d $(PREFIX)/lib $(PREFIX)/include
	install -m 644 $(LIB_STATIC) $(PREFIX)/lib/
	install -m 644 include/aes_ige_aead.h $(PREFIX)/include/
