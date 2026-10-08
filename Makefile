CC ?= cc
CFLAGS ?= -O2 -g -std=gnu11 -Wall -Wextra -fPIC
LDFLAGS ?=
BUILD := build

.PHONY: all test clean

all: $(BUILD)/librootshim.so $(BUILD)/rootbox $(BUILD)/rootshim-probe \
     $(BUILD)/rootshim-hooks $(BUILD)/repro-chroot-file $(BUILD)/repro-getgroups

$(BUILD):
	mkdir -p $@

$(BUILD)/librootshim.so: src/rootshim.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared -o $@ $< -ldl $(LDFLAGS)

$(BUILD)/rootbox: src/seccomp_supervisor.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD)/rootshim-probe: tests/rootshim_probe.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Fortified build: exercises __open_2/__openat_2 and other _FORTIFY entry points.
$(BUILD)/rootshim-hooks: tests/rootshim_hooks.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -D_FORTIFY_SOURCE=2 -o $@ $< $(LDFLAGS)

$(BUILD)/repro-chroot-file: tests/repro/chroot_file.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD)/repro-getgroups: tests/repro/getgroups.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

test: all
	sh tests/test-rootshim.sh
	sh tests/test-supervisor.sh
	sh tests/test-rootbox-combined.sh
	sh tests/test-rootshim-hooks.sh
	sh tests/test-supervisor-groups.sh
	sh tests/test-coreutils-shim.sh
	sh tests/test-debian-rootfs.sh

clean:
	rm -rf $(BUILD)
