/****************************************************************************
 * Description: Special code for fast, entire Internet-wide IPv4 probing
 *              
****************************************************************************/
#include "yarrp.h"

void internet(YarrpConfig *config, Traceroute *trace, Patricia *tree, Stats *stats) {
    uint8_t ttl;
    uint32_t val = 0;
    struct in_addr target;
    TTLHisto *ttlhisto = NULL;
    Status *status = NULL;

    uint32_t host = 1 << 24;
    char *p = NULL;
    int i;
    double prob, flip;
    uint32_t octets_to_skip[13] = {0,     /* reserved */
                                   6,     /* Army */
                                  10,     /* 1918 */
                                  11,     /* DoD */
                                  22,     /* DISA */
                                  25,     /* UK Defence */
                                  26,     /* DISA */
                                  29,     /* DISA */
                                  30,     /* DISA */
                                  55,     /* DoD */
                                 127,     /* loopback */
                                 214,     /* DoD */
                                 215,     /* DoD */
                               };

    cout << ">> Randomizing permutation." << endl;
    uint8_t key[KEYLEN] = { 0 };
    if (config->seed)
        permseed(key, config->seed);
    else
        permseed(key);
    struct cperm_t* perm = cperm_create(UINT32_MAX, PERM_MODE_CYCLE, 
                                        PERM_CIPHER_RC5, key, KEYLEN);

    p = (char *) &val;
    while (PERM_END != cperm_next(perm, &val)) {
        target.s_addr = val & 0x00FFFFFF;    // pick out 24 bits of network
        ttl = val >> 24;            // use remaining 8 bits of perm as ttl
        /* Probe a host in each /24 that's a function of the /24
           (so it appears somewhat random), but is deterministic,
           and fast to compute */
        host = (p[0] + p[1] + p[2]) & 0xFF;
        target.s_addr += (host << 24);               
        if ( (ttl & 0xE0) != 0x0) { // fast check: ttls in [0,31]
          stats->ttl_outside++;
          continue;
        }
        if (ttl >= config->maxttl)
          continue;
#if 1
        /* Only send probe if destination is in BGP table */
        status = (Status *) tree->get(target.s_addr);
        if (not status)  {
            stats->bgp_outside++;
            continue;
        }
#else
        if ( (val & 0xE0) == 0xE0) { // multicast, class E
          stats->adr_outside++;
          continue;
        }
        for (i=0;i<13;i++) {
          if ( (val & 0xFF) == octets_to_skip[i]) 
             stats->adr_outside++;
             continue;
        } 
#endif
        ttl++;                   // probe ttls from 1 to 32
#if 1
        if (ttl < config->ttl_neighborhood) {
            ttlhisto = trace->ttlhisto[ttl];
            if (ttlhisto->shouldProbe() == false) {
                stats->nbr_skipped++;
                continue;
            }
            ttlhisto->probed(trace->elapsed());
        }
#endif
        /* Running w/ a biased TTL probability distribution */
        if (config->poisson) {
            prob = poisson_pmf(ttl, config->poisson); /* poisson(k, lambda) */
            flip = zrand();  /* uniform [0.0, 1.0) */
            if (flip > prob)
                continue;
        }
        /* Passed all checks, continue and send probe */
        if (not config->testing) 
            trace->probe(target.s_addr, ttl);
        else
            trace->probePrint(&target, ttl);
        stats->count++;                
        if (stats->count == config->count)
            break;
        /* Every 4096, do this */
        if ( (stats->count & 0xFFF) == 0xFFF ) {
            if (not config->testing)
                stats->dump(stderr);
            if (config->rate) {
                /* Calculate sleep time based on scan rate */
                usleep( (1000000 / config->rate) * 4096 );
            }
        }
    }
}


/* SPECK 48/96 implementation */
#define MASK24 0xFFFFFF
#define SPECK_ROUNDS 23
#define SPECK_KEYLEN 4
#define ROR(x, r) ((x >> r) | (x << (24 - r))&MASK24)&MASK24
#define ROL(x, r) ((x << r) | (x >> (24 - r))&MASK24)&MASK24
#define R(x, y, k) (x = ROR(x, 8), x = (x + y)&MASK24, x ^= k, y = ROL(y, 3), y ^= x)
#define RR(x, y, k) (y ^= x, y = ROR(y, 3), x ^= k, x = (x - y)&MASK24, x = ROL(x, 8))

void speck_48_96_expand(uint32_t const K[SPECK_KEYLEN], uint32_t S[SPECK_ROUNDS])
{
  uint32_t i, b = K[0];
  uint32_t a[SPECK_KEYLEN - 1];

  for (i = 0; i < (SPECK_KEYLEN - 1); i++)
  {
    a[i] = K[i + 1];
  }
  S[0] = b;  
  for (i = 0; i < SPECK_ROUNDS - 1; i++) {
    R(a[i % (SPECK_KEYLEN - 1)], b, i);
    S[i + 1] = b;
  }
}

void speck_48_96_encrypt(uint32_t const pt[2], uint32_t ct[2], uint32_t const K[SPECK_ROUNDS])
{
  uint32_t i;
  ct[0]=pt[0]; ct[1]=pt[1];

  for(i = 0; i < SPECK_ROUNDS; i++){
    R(ct[1], ct[0], K[i]);
  }
}


/* Use 48 bits speck cipher:
 *   prefix = 44 bits
 *   ttl = 4 bits
 * Assume global unicast is 2000:/4, thus we generate candidate /48 prefixes
 */
void internet6(YarrpConfig *config, Traceroute *trace, Patricia *tree, Stats *stats) {
    uint8_t ttl;
    double prob, flip;
    uint64_t range = 0xFFFFFFFFFFFF;
    uint32_t buffer[2] = {0};
    uint32_t exp[SPECK_ROUNDS];
    uint32_t key[4] = {0x020100, 0x0a0908, 0x121110, 0x1a1918};
    uint32_t plain[2];
    struct in6_addr addr;
    char addrstring[INET6_ADDRSTRLEN];
    TTLHisto *ttlhisto = NULL;

    memset(&addr, 0, sizeof(struct in6_addr));
    speck_48_96_expand(key, exp);

#if 0
    uint8_t iana8[6] = {0x20, 0x24, 0x26, 0x28, 0x2a, 0x2c};
    uint16_t iana16[9] = {htons(0x2001), htons(0x2003), htons(0x2400), htons(0x2600), 
                          htons(0x2610), htons(0x2620), htons(0x2800), htons(0x2a00), 
                          htons(0x2c00)};
#endif
                         
    for (uint64_t i = 0; i<range; i++) {
        plain[0] = i & 0x00FFFFFF;
        plain[1] = (i & 0xFFFFFF000000) >> 24;
        speck_48_96_encrypt(plain, buffer, exp);
        /* magic ensues */
        addr.s6_addr[0] = 0x20 | (buffer[0] & 0xF);
        if ((addr.s6_addr[0] & 0x1) == 1) {
            stats->bgp_outside++;
            continue;
        }
        if (addr.s6_addr[0] == 0x22) {
            stats->bgp_outside++;
            continue;
        }
        if (addr.s6_addr[0] == 0x2e) {
            stats->bgp_outside++;
            continue;
        }
        addr.s6_addr[1] = (buffer[0] >> 4) & 0xFF;
        /* allow only 2800::/12, 2a00::/12, 2c00::/12 */
        if ((addr.s6_addr[0] >= 0x28) and ((addr.s6_addr[1] & 0xF0) != 0)) {
            stats->bgp_outside++;
            continue;
        }
        /* allow only 2001:: and 2003:: */
        if ((addr.s6_addr[0] == 0x20) and ((addr.s6_addr[1] & 0xFD) != 1)) {
            stats->bgp_outside++;
            continue;
        }
        if ((addr.s6_addr[0] == 0x24) and ((addr.s6_addr[1] & 0xF0) != 0)) {
            stats->bgp_outside++;
            continue;
        }

        addr.s6_addr[2] = (buffer[0] >> 12) & 0xFF;
        addr.s6_addr[3] = ((buffer[0] >> 20) & 0xF) << 4;
        addr.s6_addr[3] |= buffer[1] & 0xF;
        addr.s6_addr[4] = (buffer[1] >> 4) & 0xFF;
        addr.s6_addr[5] = (buffer[1] >> 12) & 0xFF;
#if 1
        if (tree->get(addr) == NULL) {
            stats->bgp_outside++;
            continue;
        }
#endif
        /* set bottom 32 bits to determinstic value of addr */
        addr.s6_addr32[3] = (addr.s6_addr[0] + addr.s6_addr[1]) << 5;
        addr.s6_addr32[3] += addr.s6_addr[4];
        addr.s6_addr[15] = addr.s6_addr[2] + addr.s6_addr[3] + 100;
        ttl = ((buffer[1] >> 20) & 0xF) + 1;
#if 0
        inet_ntop(AF_INET6, &addr, addrstring, INET6_ADDRSTRLEN);
        printf("Addr: %s TTL: %d\n", addrstring, ttl);
#endif
#if 1
        if (ttl < config->ttl_neighborhood) {
            ttlhisto = trace->ttlhisto[ttl];
            if (ttlhisto->shouldProbe() == false) {
                stats->nbr_skipped++;
                continue;
            }
            ttlhisto->probed(trace->elapsed());
        }
#endif
        /* Running w/ a biased TTL probability distribution */
        if (config->poisson) {
            prob = poisson_pmf(ttl, config->poisson);
            flip = zrand();
            if (flip > prob)
                continue;
        }
        trace->probe(addr, ttl);
        stats->count++;                
        if (stats->count == config->count)
            break;
        /* Every 4096, do this */
        if ( (stats->count & 0xFFF) == 0xFFF ) {
            stats->dump(stderr);
            if (config->rate) {
                /* Calculate sleep time based on scan rate */
                usleep( (1000000 / config->rate) * 4096 );
            }
        }
    }
}

