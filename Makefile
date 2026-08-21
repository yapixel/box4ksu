ifeq ($(origin CC),default)
CC = zig cc
endif
CC ?= zig cc
TARGET_TRIPLE ?= aarch64-linux-musl
CFLAGS ?= -Wall -Wextra -O2
LDFLAGS ?= -static -Wl,-s
TARGET = box
SRC = box.c
PREFIX ?= /data/adb/sing-box

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -target $(TARGET_TRIPLE) $(LDFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -d $(PREFIX)
	install -m 755 $(TARGET) $(PREFIX)/$(TARGET)

.PHONY: all clean install
