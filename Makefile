CC = zig cc
TARGET_TRIPLE ?= aarch64-linux-musl
CFLAGS ?= -Wall -Wextra -O2 -target $(TARGET_TRIPLE)
LDFLAGS ?= -static -Wl,-s
TARGET = box
SRC = box.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
