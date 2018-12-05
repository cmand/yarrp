/****************************************************************************
   Program:     $Id: $
   Date:        $Date: $ 
   Description: trace structures
****************************************************************************/

typedef enum {TR_ICMP6, TR_ICMP, TR_UDP6, TR_UDP, 
              TR_TCP6_SYN, TR_TCP_SYN, TR_TCP6_ACK, 
              TR_TCP_ACK, TR_ICMP_REPLY} traceroute_type;

static const char *Tr_Type_String[] = {"ICMP6", "ICMP", "UDP6", "UDP",
              "TCP6_SYN", "TCP_SYN", "TCP6_ACK",
              "TCP_ACK", "ICMP_REPLY"};

/* Payload for IPv6 Yarrp probes */
struct ypayload {
    uint32_t id;      /* "yrp6" = 0x79 72 70 36 */
    uint8_t instance; /* instance */
    uint8_t ttl;      /* sent TTL */
    uint16_t fudge;   /* make chksum constant */
    uint32_t diff;    /* elapsed time */
};

class Traceroute {
    public:
    Traceroute(YarrpConfig *config, Stats *stats);
    virtual ~Traceroute();
    void addTree(Patricia *_tree) {
        tree = _tree;
    }
    void addStats(Stats *_stats) {
        stats = _stats;
    }
    void initHisto(uint8_t);
    void dumpHisto();
    uint32_t elapsed();
    void openOutput(const char *);
    virtual void probe(uint32_t, int) {};
    virtual void openOutput() {};
    virtual void probe(struct sockaddr_in *, int) {};
    virtual void probePrint(struct in_addr *, int) {};
    virtual void probe(struct in6_addr, int) {};
    virtual void probePrint(struct in6_addr, int) {};

    public:
    FILE *out;   /* output file stream */
    Patricia *tree;
    Stats *stats;
    YarrpConfig *config;
    vector<TTLHisto *> ttlhisto;

    protected:
    int sndsock; /* raw socket descriptor */
    int payloadlen;
    int packlen;
    pthread_t recv_thread;
    traceroute_type tr_type;
    uint16_t dstport;
    struct timeval start;
    struct timeval now;
};

class Traceroute4 : public Traceroute {
    public:
    Traceroute4(YarrpConfig *config, Stats *stats);
    virtual ~Traceroute4();
    struct sockaddr_in *getSource() { return &source; }
    void probe(const char *, int);
    void probe(uint32_t, int);
    void probe(struct sockaddr_in *, int);
    void probePrint(struct in_addr *, int);
    void openOutput();

    private:
    void probeUDP(struct sockaddr_in *, int);
    void probeTCP(struct sockaddr_in *, int);
    void probeICMP(struct sockaddr_in *, int);
    struct ip *outip;
    struct sockaddr_in source;
};

class Traceroute6 : public Traceroute {
    public:
    Traceroute6(YarrpConfig *config, Stats *stats);
    virtual ~Traceroute6();
    struct sockaddr_in6 *getSource() { return &source6; }
    void probe(struct in6_addr, int);
    void probePrint(struct in6_addr, int);
    void probe(void *, struct in6_addr, int);
    void openOutput();

    private:
    void make_transport();
    struct ip6_hdr *outip;
    uint8_t *frame;
    int pcount;
    uint8_t tc = 0; /* traffic class which we always set to 0 */
    uint32_t flow = 0; /* flow label which we always set to 0 */
    struct sockaddr_in6 source6;
    struct ypayload *payload;
    char addrstr[INET6_ADDRSTRLEN];
};
