ifeq ($(origin CC),default)
CC = zig cc
endif
CC ?= zig cc
TARGET_TRIPLE ?= aarch64-linux-musl
CFLAGS ?= -Wall -Wextra -Oz -flto -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident
LDFLAGS ?= -static -Wl,-s -Wl,--gc-sections -Wl,--build-id=none
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
