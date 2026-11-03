TARGET ?= aarch64-linux-android
PREFIX ?= /data/adb/sing-box

# Needs the NDK linker, e.g.
# CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang
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
