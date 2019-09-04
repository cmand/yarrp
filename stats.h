#include <yarrp.h>

class Stats {
    public:
    Stats() : count(0), to_probe(0), nbr_skipped(0), bgp_skipped(0),
              ttl_outside(0), bgp_outside(0), adr_outside(0), baddst(0),
              fills(0) {
      gettimeofday(&start, NULL);
    };
    void terse() {
      terse(stderr);
    }
    void terse(FILE *out) {
      gettimeofday(&end, NULL);
      float t = (float) tsdiff(&end, &start) / 1000.0;
      fprintf(out, "# %d/%d (%2.1f%%), NBskip: %d/%d TBAout: %d/%d/%d Bad: %d Fill: %d",
        count, to_probe, (float) count*100.0/to_probe,
        nbr_skipped, bgp_skipped, ttl_outside, 
        bgp_outside, adr_outside, baddst, fills);    
      fprintf(out, " in: %2.1fs (%2.1f pps)\n",
        t, (float) count / t);
    };
    void dump(FILE *out) {
      gettimeofday(&end, NULL);
      float t = (float) tsdiff(&end, &start) / 1000.0;
      // RFC2822 timestring
      struct tm *p = localtime(&(end.tv_sec));
      char s[1000];
      strftime(s, 1000, "%a, %d %b %Y %T %z", p);
      fprintf(out, "# End: %s\n", s);
      fprintf(out, "# Bad_Resp: %u\n", baddst);
      fprintf(out, "# Fills: %u\n", fills);
      fprintf(out, "# Outside_TTL: %u\n", ttl_outside);
      fprintf(out, "# Outside_BGP: %u\n", bgp_outside);
      fprintf(out, "# Outside_Addr: %u\n", adr_outside);
      fprintf(out, "# Skipped_Nbr: %u\n", nbr_skipped);
      fprintf(out, "# Skipped_BGP: %u\n", bgp_skipped);
      fprintf(out, "# Pkts: %u\n", count);
      fprintf(out, "# Elapsed: %2.2fs\n", t);
      fprintf(out, "# PPS: %2.2f\n", (float) count / t);
      fprintf(out, "#\n");
    };
    
    uint32_t count;       // number of probes sent
    uint32_t to_probe;
    uint32_t nbr_skipped; // b/c already in learned neighborhood 
    uint32_t bgp_skipped; // b/c BGP learned
    uint32_t ttl_outside; // b/c outside range of TTLs we want
    uint32_t bgp_outside; // b/c not in BGP table
    uint32_t adr_outside; // b/c address outside range we want
    uint32_t baddst;      // b/c checksum invalid on destination in reponse
    uint32_t fills;       // extra tail probes past maxttl
   
    struct timeval start;
    struct timeval end;
};
