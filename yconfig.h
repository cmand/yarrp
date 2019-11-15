typedef std::pair<std::string, bool> val_t;
typedef std::map<std::string, val_t> params_t;

class YarrpConfig {
  public:
  YarrpConfig() : rate(10), random_scan(true), ttl_neighborhood(0),
    testing(false), entire(false), output(NULL), 
    bgpfile(NULL), inlist(NULL), blocklist(NULL),
    count(0), minttl(1), maxttl(16), seed(0),
    dstport(80),
    ipv6(false), int_name(NULL), dstmac(NULL), srcmac(NULL), srcaddr(NULL),
    coarse(false), fillmode(32), poisson(0),
    probesrc(NULL), probe(true), receive(true), instance(0), out(NULL) {};

  void parse_opts(int argc, char **argv); 
  void usage(char *prog);
  void set(std::string, std::string, bool);
  void dump() { if (output) dump(out); }
  unsigned int rate;
  bool random_scan;
  uint8_t ttl_neighborhood;
  bool testing; 
  bool entire;  /* speed as sole emphasis, to scan entire Internet */
  char *output;
  char *bgpfile;
  char *inlist;
  char *blocklist;
  uint32_t count;
  uint8_t minttl;
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
  FILE *out;   /* output file stream */
  params_t params;

  private:
  void dump(FILE *fd);
};
