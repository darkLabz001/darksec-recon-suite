CC      ?= cc
CFLAGS  ?= -std=gnu11 -O2 -Wall -Wextra
PREFIX  ?= /usr/local
TARGET   = ch1m3ra

# ch1m3ra is split into modules, all sharing ch1m3ra.h.
# globals.c holds the shared state (cfg, stats, signal flag, buckets).
SRCS = globals.c util.c decode.c app.c harvest.c recon.c flows.c frag.c filter.c \
       print.c pcap.c bpf.c capture.c tui.c config.c defense.c craft.c main.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c ch1m3ra.h
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TARGET) tests/sample.pcap tests/creds.pcap tests/frag.pcap tests/tls.pcap tests/quic.pcap tests/h2.pcap tests/metrics.pcap tests/proto.pcap tests/defense.pcap tests/wlan.pcap
	./$(TARGET) -r tests/sample.pcap -C -B 32
	@echo
	BIN=./$(TARGET) sh tests/check.sh

# Sanitizer build for the test suite (ASan + UBSan).
asan: CFLAGS = -std=gnu11 -O1 -g -fsanitize=address,undefined -Wall -Wextra
asan: clean $(TARGET)

# Live-capture + injection harness over network namespaces (needs root).
# Skips cleanly when unprivileged, so it can be run unconditionally.
netns: $(TARGET)
	BIN=./$(TARGET) sh tests/netns.sh

# Live 802.11 injection test (needs root + a monitor-capable radio).
# Skips cleanly when unprivileged or no radio is available.
wlan: $(TARGET)
	BIN=./$(TARGET) sh tests/wlan_live.sh

# Behavior gate: replay the invocation matrix that produced the frozen
# .baseline/ch1m3ra.out and show the diff (intended changes only).
gate: $(TARGET)
	@sh tests/gate.sh

# Structure-aware fuzz of the decode pipeline under ASan+UBSan.
# Separate binary (fuzz.c defines main()) so it never links into ch1m3ra.
FUZZSRCS = globals.c util.c decode.c app.c harvest.c recon.c flows.c frag.c \
           filter.c print.c pcap.c bpf.c capture.c craft.c tui.c config.c defense.c
fuzz: CFLAGS = -std=gnu11 -O1 -g -fsanitize=address,undefined -Wall -Wextra
fuzz: fuzz.c $(FUZZSRCS) ch1m3ra.h
	$(CC) $(CFLAGS) -o fuzz fuzz.c $(FUZZSRCS)

tests/sample.pcap: tests/gen_pcap.py
	python3 tests/gen_pcap.py > $@

tests/creds.pcap: tests/gen_creds.py
	python3 tests/gen_creds.py $@

tests/frag.pcap: tests/gen_frag.py
	python3 tests/gen_frag.py $@

tests/quic.pcap: tests/gen_quic.py
	python3 tests/gen_quic.py $@

tests/h2.pcap: tests/gen_h2.py
	python3 tests/gen_h2.py $@

tests/metrics.pcap: tests/gen_metrics.py
	python3 tests/gen_metrics.py $@

tests/proto.pcap: tests/gen_proto.py
	python3 tests/gen_proto.py $@

tests/defense.pcap: tests/gen_defense.py
	python3 tests/gen_defense.py $@

tests/wlan.pcap: tests/gen_wlan.py
	python3 tests/gen_wlan.py $@

tests/tls.pcap: tests/gen_tls.py
	python3 tests/gen_tls.py $@

# Regenerate the module .c files from the frozen single-file original.
modules: ch1m3ra.c tools/split.py
	python3 tools/split.py

install: $(TARGET)
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 644 ch1m3ra.1 $(DESTDIR)$(PREFIX)/share/man/man1/ch1m3ra.1

clean:
	rm -f $(TARGET) $(OBJS) fuzz

.PHONY: all test asan modules install clean netns gate fuzz wlan
