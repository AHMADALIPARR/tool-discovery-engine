// discover.c — the Tool Discovery Engine (C11, zero dependencies).
//
// The registry models every agent tool two evidence-graded source
// inventories know (922 records at first ingest). An agent does NOT
// preload those records into its context. It carries five verbs —
// coverage, search, describe, match, verify — and pulls the few
// tool definitions a task actually needs. Context is what the
// agent does not need to carry; discovery carries it instead.
//
//   discover [--registry DIR] coverage
//   discover [--registry DIR] search <term> [term...]
//   discover [--registry DIR] describe <index>
//   discover [--registry DIR] describe <provider> <tool>
//   discover [--registry DIR] match "<task text>"
//   discover [--registry DIR] verify
//
// Exit codes: 0 ok · 2 usage · 3 not found · 4 seal refused.

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

// ---------------- SHA-256 (FIPS 180-4) ----------------
typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t n; } sha256_ctx;
static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha_block(sha256_ctx *c, const uint8_t *p) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[i*4]<<24 | (uint32_t)p[i*4+1]<<16 | (uint32_t)p[i*4+2]<<8 | p[i*4+3];
  for (int i = 16; i < 64; i++) { uint32_t s0 = RR(w[i-15],7)^RR(w[i-15],18)^(w[i-15]>>3); uint32_t s1 = RR(w[i-2],17)^RR(w[i-2],19)^(w[i-2]>>10); w[i] = w[i-16]+s0+w[i-7]+s1; }
  uint32_t a=c->h[0],b=c->h[1],d=c->h[3],e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7],cc=c->h[2];
  for (int i = 0; i < 64; i++) { uint32_t S1=RR(e,6)^RR(e,11)^RR(e,25); uint32_t ch=(e&f)^(~e&g); uint32_t t1=h+S1+ch+K[i]+w[i]; uint32_t S0=RR(a,2)^RR(a,13)^RR(a,22); uint32_t mj=(a&b)^(a&cc)^(b&cc); uint32_t t2=S0+mj; h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2; }
  c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d; c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}
static void sha_init(sha256_ctx *c) { memcpy(c->h, "\x6a\x09\xe6\x67\xbb\x67\xae\x85\x3c\xef\x37\x24\x3a\x54\xfa\xa5\xab\xf5\x3f\x82\x51\x80\x9b\x68\x8d\x2f\x00\x00\x00\x00\x00\x00", 0); // placeholder, set below
  static const uint32_t H0[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  memcpy(c->h, H0, sizeof H0); c->len = 0; c->n = 0; }
static void sha_update(sha256_ctx *c, const void *data, size_t len) {
  const uint8_t *p = data; c->len += len;
  while (len) { size_t take = 64 - c->n; if (take > len) take = len; memcpy(c->buf + c->n, p, take); c->n += take; p += take; len -= take; if (c->n == 64) { sha_block(c, c->buf); c->n = 0; } }
}
static void sha_final(sha256_ctx *c, char out[65]) {
  uint64_t bits = c->len * 8; uint8_t pad = 0x80; sha_update(c, &pad, 1);
  uint8_t z = 0; while (c->n != 56) sha_update(c, &z, 1);
  uint8_t lb[8]; for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - 8*i));
  // append length directly (bypass len counter)
  memcpy(c->buf + c->n, lb, 8); sha_block(c, c->buf);
  static const char *hex = "0123456789abcdef";
  for (int i = 0; i < 8; i++) for (int j = 3; j >= 0; j--) { uint8_t b = (uint8_t)(c->h[i] >> (j*8)); out[i*8 + (3-j)*2] = hex[b>>4]; out[i*8 + (3-j)*2 + 1] = hex[b&15]; }
  out[64] = 0;
}
static void sha256_hex(const char *s, char out[65]) { sha256_ctx c; sha_init(&c); sha_update(&c, s, strlen(s)); sha_final(&c, out); }

// ---------------- registry ----------------
typedef struct { char *provider, *name, *category, *tier, *avail, *url; int params; } Tool;
static Tool *tools; static int ntools;
static char regdir[512] = "registry";

static char *xstrdup(const char *s) { size_t n = strlen(s) + 1; char *p = malloc(n); memcpy(p, s, n); return p; }
static void lower(char *s) { for (; *s; s++) *s = tolower((unsigned char)*s); }
static int contains_ci(const char *hay, const char *needle) {
  if (!*needle) return 1;
  size_t hn = strlen(hay), nn = strlen(needle);
  for (size_t i = 0; i + nn <= hn; i++) { size_t j = 0; while (j < nn && tolower((unsigned char)hay[i+j]) == tolower((unsigned char)needle[j])) j++; if (j == nn) return 1; }
  return 0;
}
static int load_registry(void) {
  char path[600]; snprintf(path, sizeof path, "%s/tools.tsv", regdir);
  FILE *f = fopen(path, "r");
  if (!f) { fprintf(stderr, "cannot open %s — run the ingest first\n", path); return -1; }
  char line[8192]; int cap = 1024; tools = malloc(sizeof(Tool) * cap);
  while (fgets(line, sizeof line, f)) {
    line[strcspn(line, "\n")] = 0;
    if (!line[0]) continue;
    if (ntools == cap) { cap *= 2; tools = realloc(tools, sizeof(Tool) * cap); }
    Tool *t = &tools[ntools]; memset(t, 0, sizeof *t);
    char *fields[7]; int nf = 0; char *p = line;
    while (nf < 7) { fields[nf++] = p; char *tab = strchr(p, '\t'); if (!tab) break; *tab = 0; p = tab + 1; }
    if (nf < 7) continue;
    t->provider = xstrdup(fields[0]); t->name = xstrdup(fields[1]); t->category = xstrdup(fields[2]);
    t->tier = xstrdup(fields[3]); t->avail = xstrdup(fields[4]); t->params = fields[5][0] == '1'; t->url = xstrdup(fields[6]);
    ntools++;
  }
  fclose(f);
  return 0;
}
static long file_size(const char *path) { FILE *f = fopen(path, "rb"); if (!f) return -1; fseek(f, 0, SEEK_END); long n = ftell(f); fclose(f); return n; }

static int cmd_coverage(void) {
  const char *tiers[] = {"T1","T2","T3","T4","T5"};
  printf("tool discovery — coverage\n  records: %d\n", ntools);
  for (int i = 0; i < 5; i++) { int n = 0, np = 0; for (int j = 0; j < ntools; j++) if (!strcmp(tools[j].tier, tiers[i])) { n++; np += tools[j].params; } printf("  %s: %d\n", tiers[i], n); }
  int providers = 0; for (int j = 0; j < ntools; j++) { int seen = 0; for (int k = 0; k < j; k++) if (!strcmp(tools[k].provider, tools[j].provider)) { seen = 1; break; } providers += !seen; }
  printf("  providers: %d\n", providers);
  char path[600]; snprintf(path, sizeof path, "%s/tools.jsonl", regdir);
  long bytes = file_size(path);
  printf("  context math: preloading every record costs %ld bytes of tool definitions;\n", bytes);
  printf("  the discovery surface an agent carries instead is 5 verbs (coverage, search,\n  describe, match, verify) plus the few records a match returns.\n");
  return 0;
}
static int tier_rank(const char *t) { return t[1] - '0'; }
static int cmd_search(int argc, char **argv) {
  int shown = 0;
  for (int pass = 0; pass < 2 && shown < 25; pass++)
    for (int j = 0; j < ntools && shown < 25; j++) {
      int namehit = 0, any = 1;
      for (int a = 0; a < argc; a++) { if (contains_ci(tools[j].name, argv[a])) namehit = 1; if (!contains_ci(tools[j].provider, argv[a]) && !contains_ci(tools[j].name, argv[a]) && !contains_ci(tools[j].category, argv[a])) any = 0; }
      if (!any || (pass == 0) != (namehit > 0)) continue;
      printf("%4d  %-28s %-34s %-38s %s%s\n", j + 1, tools[j].provider, tools[j].name, tools[j].category, tools[j].tier, tools[j].params ? "  [schema]" : "");
      shown++;
    }
  if (!shown) { printf("no tools match\n"); return 3; }
  return 0;
}
static int cmd_describe(int argc, char **argv) {
  int idx = -1;
  if (argc == 1 && atoi(argv[0]) > 0) idx = atoi(argv[0]);
  else if (argc == 1) { for (int j = 0; j < ntools; j++) if (!strcmp(tools[j].name, argv[0])) { idx = j + 1; break; } }
  else if (argc == 2) {
    for (int j = 0; j < ntools; j++) if (!strcmp(tools[j].provider, argv[0]) && !strcmp(tools[j].name, argv[1])) { idx = j + 1; break; }
    if (idx < 0) { const char *p2 = !strncmp(argv[0], "MCP ", 4) ? argv[0] + 4 : argv[0]; for (int j = 0; j < ntools; j++) if (!strcmp(tools[j].provider, p2) && !strcmp(tools[j].name, argv[1])) { idx = j + 1; break; } }
    if (idx < 0) for (int j = 0; j < ntools; j++) if (contains_ci(tools[j].provider, argv[0]) && !strcmp(tools[j].name, argv[1])) { idx = j + 1; break; }
  }
  if (idx < 1 || idx > ntools) { printf("record not found\n"); return 3; }
  char path[600]; snprintf(path, sizeof path, "%s/records/%d.json", regdir, idx);
  FILE *f = fopen(path, "r"); if (!f) { printf("record file missing\n"); return 3; }
  char buf[16384]; size_t n = fread(buf, 1, sizeof buf - 1, f); buf[n] = 0; fclose(f);
  printf("%s", buf);
  return 0;
}
static int cmd_match(const char *task) {
  char tmp[1024]; snprintf(tmp, sizeof tmp, "%s", task); lower(tmp);
  char *toks[32]; int nt = 0; char *save = NULL;
  for (char *t = strtok_r(tmp, " ,.;:!?/\\_-", &save); t && nt < 32; t = strtok_r(NULL, " ,.;:!?/\\_-", &save)) if (strlen(t) > 2) toks[nt++] = t;
  typedef struct { int idx, score; } Hit; Hit hits[4096]; int nh = 0;
  for (int j = 0; j < ntools; j++) {
    int score = 0;
    for (int a = 0; a < nt; a++) { if (contains_ci(tools[j].name, toks[a])) score += 3; if (contains_ci(tools[j].category, toks[a])) score += 2; if (contains_ci(tools[j].provider, toks[a])) score += 1; }
    if (score > 0) { hits[nh].idx = j; hits[nh].score = score; nh++; }
  }
  for (int i = 0; i < nh; i++) for (int k = i + 1; k < nh; k++) if (hits[k].score > hits[i].score || (hits[k].score == hits[i].score && tier_rank(tools[hits[k].idx].tier) < tier_rank(tools[hits[i].idx].tier))) { Hit t = hits[i]; hits[i] = hits[k]; hits[k] = t; }
  int shown = nh < 10 ? nh : 10;
  if (!shown) { printf("no candidate tools for that task\n"); return 3; }
  printf("candidate tools for: %s\n", task);
  for (int i = 0; i < shown; i++) { Tool *t = &tools[hits[i].idx]; printf("%4d  score=%-3d %-28s %-34s %s%s\n", hits[i].idx + 1, hits[i].score, t->provider, t->name, t->tier, t->params ? "  [schema]" : ""); }
  printf("load only these: discover describe <index> for the full record\n");
  return 0;
}
static int cmd_verify(void) {
  char path[600], genesis[600] = "", head[65] = ""; long want = -1;
  snprintf(path, sizeof path, "%s/SEAL.txt", regdir);
  FILE *f = fopen(path, "r"); if (!f) { printf("SEAL.txt missing — registry REFUSED\n"); return 4; }
  char line[1024];
  while (fgets(line, sizeof line, f)) { if (!strncmp(line, "genesis: ", 9)) snprintf(genesis, sizeof genesis, "%s", line + 9); if (!strncmp(line, "head: ", 6)) snprintf(head, sizeof head, "%s", line + 6); if (!strncmp(line, "records: ", 9)) want = atol(line + 9); }
  fclose(f); genesis[strcspn(genesis, "\n")] = 0; head[strcspn(head, "\n")] = 0;
  snprintf(path, sizeof path, "%s/tools.jsonl", regdir);
  f = fopen(path, "r"); if (!f) { printf("tools.jsonl missing — registry REFUSED\n"); return 4; }
  char tip[1200]; snprintf(tip, sizeof tip, "%s", genesis);
  char rline[16384]; long n = 0;
  while (fgets(rline, sizeof rline, f)) { rline[strcspn(rline, "\n")] = 0; if (!rline[0]) continue; char joined[20000]; snprintf(joined, sizeof joined, "%s|%s", tip, rline); sha256_hex(joined, tip); n++; }
  fclose(f);
  // tip now holds a hex head; chain used hex strings as links
  if (n == want && !strcmp(tip, head)) { printf("seal VALID — %ld records, head %s\n", n, head); return 0; }
  printf("seal REFUSED — chain does not recompute (records %ld/%ld)\n", n, want);
  return 4;
}

int main(int argc, char **argv) {
  int a = 1;
  if (a + 1 < argc && !strcmp(argv[a], "--registry")) { snprintf(regdir, sizeof regdir, "%s", argv[a + 1]); a += 2; }
  if (a >= argc) { fprintf(stderr, "usage: discover [--registry DIR] coverage|search|describe|match|verify\n"); return 2; }
  const char *cmd = argv[a];
  if (!strcmp(cmd, "verify")) { /* verify loads the seal, not the TSV */ if (load_registry()) return 4; return cmd_verify(); }
  if (load_registry()) return 2;
  if (!strcmp(cmd, "coverage")) return cmd_coverage();
  if (!strcmp(cmd, "search")) { if (a + 1 >= argc) return 2; return cmd_search(argc - a - 1, argv + a + 1); }
  if (!strcmp(cmd, "describe")) { if (a + 1 >= argc) return 2; return cmd_describe(argc - a - 1, argv + a + 1); }
  if (!strcmp(cmd, "match")) { if (a + 1 >= argc) return 2; return cmd_match(argv[a + 1]); }
  fprintf(stderr, "unknown command: %s\n", cmd);
  return 2;
}
