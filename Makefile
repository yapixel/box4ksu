TARGET ?= aarch64-unknown-linux-musl
PREFIX ?= /data/adb/sing-box

all:
	cargo build --release --target $(TARGET)
	cp target/$(TARGET)/release/box box

test:
	cargo test

clean:
	cargo clean
	rm -f box

install: all
	install -d $(PREFIX)
	install -m 755 box $(PREFIX)/box

.PHONY: all test clean install
