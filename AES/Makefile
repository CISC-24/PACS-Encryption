# Makefile for compiling aes_encrypt.c and aes_decrypt.c

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -lssl -lcrypto

# Targets
TARGETS = aes_encrypt aes_decrypt

# Source files
SRC1 = aes_encrypt.c
SRC2 = aes_decrypt.c

# Default target
all: $(TARGETS)

# Build target 1
aes_encrypt: $(SRC1)
	$(CC) -o aes_encrypt $(SRC1) $(CFLAGS)

# Build target 2
aes_decrypt: $(SRC2)
	$(CC) -o aes_decrypt $(SRC2) $(CFLAGS)

# Clean up generated files
.PHONY: clean
clean:
	rm -f $(TARGETS)
