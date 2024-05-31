# Makefile for compiling aria_encrypt.c and aria_decrypt.c

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -lssl -lcrypto

# Targets
TARGETS = aria_encrypt aria_decrypt

# Source files
SRC1 = aria_encrypt.c
SRC2 = aria_decrypt.c
# Default target
all: $(TARGETS)

# Build target 1
aria_encrypt: $(SRC1)
	$(CC) -o aria_encrypt $(SRC1) $(CFLAGS)

# Build target 2
aria_decrypt: $(SRC2)
	$(CC) -o aria_decrypt $(SRC2) $(CFLAGS)



# Clean up generated files
.PHONY: clean
clean:
	rm -f $(TARGETS)
