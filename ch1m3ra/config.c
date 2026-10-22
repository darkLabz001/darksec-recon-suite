/* config.c - save/load persistent settings to a small key=value rc file.
 *
 * The TUI is configurable live (filters + which analyses are on); this lets an
 * analyst keep a setup between runs.  The file is intentionally simple: one
 * "key = value" per line, '#' comments, unknown keys ignored, so it stays
 * hand-editable and forward/backward compatible.
 *
 * Only settings that make sense to persist are written -- never capture-source
 * or output-file paths, which are per-invocation.
 */
#include "ch1m3ra.h"
#include <ctype.h>

#define CONFIG_PATH ".ch1m3rarc"

/* strip leading/trailing whitespace in place, return the trimmed start */
static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
    return s;
}

static int truthy(const char *v) {
    return !strcasecmp(v, "1") || !strcasecmp(v, "on") ||
           !strcasecmp(v, "true") || !strcasecmp(v, "yes");
}

const char *config_path(void) {
    static char path[4096];
    const char *home = getenv("HOME");
    snprintf(path, sizeof path, "%s/%s", home ? home : ".", CONFIG_PATH);
    return path;
}

int config_save(char *err, size_t errsz) {
    const char *path = config_path();
    FILE *f = fopen(path, "w");
    if (!f) {
        if (err) snprintf(err, errsz, "cannot write %s: %s", path, strerror(errno));
        return -1;
    }
    fprintf(f, "# ch1m3ra rc - written by ':save' / --save-config\n");
    fprintf(f, "color       = %d\n", cfg.color ? 1 : 0);
    fprintf(f, "promisc     = %d\n", cfg.nopromisc ? 0 : 1);
    fprintf(f, "snaplen     = %ld\n", cfg.snaplen);
    fprintf(f, "dumpbytes   = %ld\n", cfg.dumpbytes);
    fprintf(f, "outfmt      = %s\n", cfg.outfmt ? cfg.outfmt : "text");
    fprintf(f, "reasm       = %d\n", cfg.reasm ? 1 : 0);
    fprintf(f, "harvest     = %d\n", cfg.harvest ? 1 : 0);
    fprintf(f, "finger      = %d\n", cfg.finger ? 1 : 0);
    fprintf(f, "talkers     = %d\n", cfg.talkers ? 1 : 0);
    fprintf(f, "names       = %d\n", cfg.names ? 1 : 0);
    fprintf(f, "evasion     = %d\n", cfg.evasion ? 1 : 0);
    fprintf(f, "ring        = %d\n", cfg.ring ? 1 : 0);
    /* filters are optional */
    if (cfg.proto) fprintf(f, "proto       = %s\n", cfg.proto);
    if (cfg.host)  fprintf(f, "host        = %s\n", cfg.host);
    if (cfg.port >= 0) fprintf(f, "port        = %ld\n", cfg.port);
    if (cfg.bfilter) fprintf(f, "bpf         = %s\n", cfg.bfilter);
    if (fclose(f) != 0) {
        if (err) snprintf(err, errsz, "write error on %s", path);
        return -1;
    }
    if (err) snprintf(err, errsz, "saved %s", path);
    return 0;
}

int config_load(const char *path, char *err, size_t errsz) {
    if (!path) path = config_path();
    FILE *f = fopen(path, "r");
    if (!f) {
        if (err) snprintf(err, errsz, "cannot read %s: %s", path, strerror(errno));
        return -1;
    }
    char line[512];
    int nset = 0;
    while (fgets(line, sizeof line, f)) {
        char *s = trim(line);
        if (!*s || *s == '#') continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = 0;
        char *key = trim(s);
        char *val = trim(eq + 1);
        if (!strcasecmp(key, "color"))          cfg.color = truthy(val);
        else if (!strcasecmp(key, "promisc"))   cfg.nopromisc = !truthy(val);
        else if (!strcasecmp(key, "snaplen"))   cfg.snaplen = strtol(val, NULL, 10);
        else if (!strcasecmp(key, "dumpbytes")) cfg.dumpbytes = strtol(val, NULL, 10);
        else if (!strcasecmp(key, "outfmt") || !strcasecmp(key, "format"))
            cfg.outfmt = strdup(val);
        else if (!strcasecmp(key, "reasm"))     cfg.reasm = truthy(val);
        else if (!strcasecmp(key, "harvest"))   cfg.harvest = truthy(val);
        else if (!strcasecmp(key, "finger"))    cfg.finger = truthy(val);
        else if (!strcasecmp(key, "talkers"))   cfg.talkers = truthy(val);
        else if (!strcasecmp(key, "names"))     cfg.names = truthy(val);
        else if (!strcasecmp(key, "evasion"))   cfg.evasion = truthy(val);
        else if (!strcasecmp(key, "ring"))      cfg.ring = truthy(val);
        else if (!strcasecmp(key, "proto"))     cfg.proto = strdup(val);
        else if (!strcasecmp(key, "host"))      cfg.host = strdup(val);
        else if (!strcasecmp(key, "port"))      cfg.port = strtol(val, NULL, 10);
        else if (!strcasecmp(key, "bpf"))       cfg.bfilter = strdup(val);
        else continue;                          /* unknown key: ignore */
        nset++;
    }
    fclose(f);
    if (err) snprintf(err, errsz, "loaded %s (%d settings)", path, nset);
    return 0;
}
