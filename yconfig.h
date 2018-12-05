class YarrpConfig {
  public:
  YarrpConfig() : rate(10), random_scan(true), ttl_neighborhood(0),
    testing(false), entire(false), output(NULL), 
    bgpfile(NULL), inlist(NULL), count(0), maxttl(32), seed(0),
    dstport(80),
    ipv6(false), int_name(NULL), dstmac(NULL), srcmac(NULL), srcaddr(NULL),
    coarse(false), fillmode(0), poisson(0),
    probesrc(NULL), probe(true), receive(true), instance(0) {};

  void parse_opts(int argc, char **argv); 
  void usage(char *prog);
  unsigned int rate;
  bool random_scan;
  uint8_t ttl_neighborhood;
  bool testing; 
  bool entire;  /* speed as sole emphasis, to scan entire Internet */
  char *output;
  char *bgpfile;
  char *inlist;
  uint32_t count;
  uint8_t maxttl;
  uint32_t seed;
  uint16_t dstport;
  bool ipv6;
  char *int_name;
  uint8_t *dstmac;
  uint8_t *srcmac;
  struct in6_addr *srcaddr;
  int type;
  bool coarse;
  int fillmode;
  int poisson;
  char *probesrc;
  bool probe;
  bool receive;
  uint8_t instance;
};
