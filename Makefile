CC ?= cc
CFLAGS ?= -O2 -g -std=gnu11 -Wall -Wextra -fPIC
LDFLAGS ?=
BUILD := build

.PHONY: all test clean

all: $(BUILD)/librootshim.so $(BUILD)/rootbox $(BUILD)/rootshim-probe

$(BUILD):
	mkdir -p $@

$(BUILD)/librootshim.so: src/rootshim.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared -o $@ $< -ldl $(LDFLAGS)

$(BUILD)/rootbox: src/seccomp_supervisor.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD)/rootshim-probe: tests/rootshim_probe.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

test: all
	sh tests/test-rootshim.sh
	sh tests/test-supervisor.sh
	sh tests/test-rootbox-combined.sh

clean:
	rm -rf $(BUILD)
