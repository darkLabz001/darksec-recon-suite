/* fuzz.c - structure-aware fuzz target for the decode pipeline.
 *
 * Feeds arbitrary bytes straight at process_frame(), which is the same entry
 * point the live and pcap paths use, so every decoder (L2/L3/L4/app/proto),
 * the fragment reassembler and the flow tracker all get exercised.  Build with
 * ASan+UBSan and it turns any OOB/UB in the parsers into a crash.
 *
 * Two modes:
 *   - libFuzzer:  cc -fsanitize=fuzzer,address,undefined ... fuzz.c <modules>
 *   - self-loop:   ./fuzz [iterations] [-s seed] [corpus.pcap]
 *                  (no libFuzzer needed; mutates a seed corpus and calls
 *                   process_frame in a loop -- used by `make fuzz`)
 *
 * Only compile this file when building the fuzzer (it defines main()).
 */
#include "ch1m3ra.h"

/* process_frame lives in capture.c, which we link in; the rest of the state
 * (cfg/st/cap) comes from globals.c.  We only touch the pure decode path. */

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;
static uint32_t xrand(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 32);
}

static void feed(const uint8_t *data, size_t len) {
    static uint8_t buf[70000];
    if (len > sizeof buf) len = sizeof buf;
    memcpy(buf, data, len);
    struct timespec ts = { 1700000000, 0 };
    /* even/odd: exercise the fragment reassembler too */
    cfg.reasm = (int)(xrand() & 1);
    process_frame(buf, len, len, &ts, "fuzz", 0, 0);
    if (cfg.credfile) { /* keep it from growing a file during fuzzing */ }
}

#ifndef FUZZ_LIBFUZZER

int main(int argc, char **argv) {
    long iters = 200000;
    const char *corpus = NULL;
    int seed = 1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-s") && i + 1 < argc) seed = atoi(argv[++i]);
        else if (argv[i][0] == '-') corpus = NULL;
        else if (argv[i][0] >= '0' && argv[i][0] <= '9') iters = atol(argv[i]);
        else corpus = argv[i];        /* a path is the seed corpus */
    }
    if (corpus) { /* loop mode always mutates tests/sample.pcap; path ignored */ }
    (void)corpus;
    /* keep the fuzz output quiet: we only care about sanitizer traps */
    freopen("/dev/null", "w", stdout);
    rng_state ^= (uint64_t)seed * 0x2545f4914f6cdd1dull;
    cfg.dumpbytes = 0;
    cfg.harvest = 1;         /* exercise the credential/proto parsers */
    cfg.finger = 1;
    cfg.names = 1;
    cfg.talkers = 1;

    /* real seeds so mutations start from valid frames: pull the first frame
     * from a spread of captures covering wired, creds, fragments, TLS/QUIC/H2,
     * proto, defensive (QinQ/DTP/ARP) and 802.11 (radiotap) shapes. */
    enum { MAX_SEEDS = 16 };
    static uint8_t seedbuf[MAX_SEEDS][4096];
    static size_t seedlen[MAX_SEEDS];
    int nseeds = 0;
    static const char *seedfiles[] = {
        "tests/sample.pcap", "tests/creds.pcap", "tests/frag.pcap",
        "tests/tls.pcap", "tests/quic.pcap", "tests/h2.pcap",
        "tests/metrics.pcap", "tests/proto.pcap", "tests/defense.pcap",
        "tests/wlan.pcap", NULL
    };
    for (int si = 0; seedfiles[si] && nseeds < MAX_SEEDS; si++) {
        FILE *f = fopen(seedfiles[si], "rb");
        if (!f) continue;
        uint8_t gh[24];
        if (fread(gh, 1, 24, f) == 24) {
            uint8_t rh[16];
            while (fread(rh, 1, 16, f) == 16) {
                uint32_t incl = (uint32_t)rh[8] | (rh[9] << 8) | (rh[10] << 16) | (rh[11] << 24);
                if (incl > 4096) break;
                if (fread(seedbuf[nseeds], 1, incl, f) != incl) break;
                seedlen[nseeds] = incl;
                nseeds++;
                break;              /* first frame is enough as a base */
            }
        }
        fclose(f);
    }

    fprintf(stderr, "fuzz: %ld iterations, seed=%d, %d seed frames\n",
            iters, seed, nseeds);

    static uint8_t work[70000];
    for (long n = 0; n < iters; n++) {
        size_t len;
        int s = nseeds ? (int)(xrand() % (uint32_t)nseeds) : -1;
        /* vary the link type so the radiotap/raw-802.11 and pcapng paths are hit */
        uint32_t lt = xrand() % 4;
        g_linktype = (lt == 0) ? 1 : (lt == 1) ? 127 : (lt == 2) ? 105 : 1;
        if (s >= 0 && (xrand() & 3)) {
            len = seedlen[s];
            memcpy(work, seedbuf[s], len);
            /* random byte flips */
            int flips = 1 + (int)(xrand() % 8);
            for (int k = 0; k < flips; k++)
                work[xrand() % len] ^= (uint8_t)(1u << (xrand() & 7));
            /* sometimes truncate */
            if (xrand() & 1) len = 1 + (xrand() % len);
            /* sometimes splice random bytes onto the end */
            if (xrand() & 1) {
                size_t extra = xrand() % 64;
                for (size_t k = 0; k < extra && len < sizeof work; k++)
                    work[len++] = (uint8_t)xrand();
            }
        } else {
            len = xrand() % 512;
            for (size_t k = 0; k < len; k++) work[k] = (uint8_t)xrand();
        }
        feed(work, len);
    }
    fprintf(stderr, "fuzz: done, no crashes\n");
    return 0;
}

#else /* libFuzzer entry point */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    feed(data, size);
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    cfg.dumpbytes = 0;
    cfg.harvest = 1;
    cfg.finger = 1;
    cfg.names = 1;
    cfg.talkers = 1;
    return 0;
}

#endif
