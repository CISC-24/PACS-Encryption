# Makefile for compiling aes_encrypt_backup.c and aria_encrypt_backup.c

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -lssl -lcrypto

# Targets
TARGETS = 123 456

# Source files
SRC1 = aes_encrypt_backup.c
SRC2 = aria_encrypt_backup.c

# Default target
all: $(TARGETS)

# Build target 1
123: $(SRC1)
	$(CC) -o 123 $(SRC1) $(CFLAGS)

# Build target 2
456: $(SRC2)
	$(CC) -o 456 $(SRC2) $(CFLAGS)

# Clean up generated files
.PHONY: clean
clean:
	rm -f $(TARGETS)
