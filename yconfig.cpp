/****************************************************************************
   Program:     $Id: $
   Date:        $Date: $
   Description: yarrp runtime configuration parsing
****************************************************************************/
#include "yarrp.h"

int verbosity;

static struct option long_options[] = {
    {"srcaddr", required_argument, NULL, 'a'},
    {"bgp", required_argument, NULL, 'b'},
    {"coarse", required_argument, NULL, 'C'},
    {"count", required_argument, NULL, 'c'},
    {"fillmode", required_argument, NULL, 'F'},
    {"poisson", required_argument, NULL, 'B'},
    {"srcmac", required_argument, NULL, 'M'},
    {"help", no_argument, NULL, 'h'},
    {"input", required_argument, NULL, 'i'},
    {"interface", required_argument, NULL, 'I'},
    {"maxttl", required_argument, NULL, 'm'},
    {"dstmac", required_argument, NULL, 'G'},
    {"neighborhood", required_argument, NULL, 'n'},
    {"output", required_argument, NULL, 'o'},
    {"port", required_argument, NULL, 'p'}, 
    {"probeonly", required_argument, NULL, 'P'}, 
    {"entire", no_argument, NULL, 'Q'},
    {"rate", required_argument, NULL, 'r'},
    {"receiveonly", required_argument, NULL, 'R'},
    {"sequential", no_argument, NULL, 's'},
    {"seed", required_argument, NULL, 'S'},
    {"type", required_argument, NULL, 't'},
    {"verbose", no_argument, NULL, 'v'},
    {"testing", no_argument, NULL, 'T'},
    {"instance", required_argument, NULL, 'E'}, 
    {NULL, 0, NULL, 0},
};

uint8_t *read_mac(char *str) {
    uint8_t *mac = (uint8_t *) malloc (6 * sizeof(uint8_t));
    mac[0] = (uint8_t) strtoul(strtok(str, ":"), NULL, 16);
    for (int i=1; i < 6; i++) 
        mac[i] = (uint8_t) strtoul(strtok(NULL, ":"), NULL, 16);
    return mac;
}

struct in6_addr *read_v6_src_addr(char *str) {
    in6_addr *src = (in6_addr *) malloc(sizeof(in6_addr));
    inet_pton(AF_INET6, str, src);
    return src;
}

void
YarrpConfig::parse_opts(int argc, char **argv) {
    int c, opt_index;
    char *endptr;

    if (argc <= 1)
        usage(argv[0]);
    type = TR_TCP_ACK;
    seed = time(NULL);
    while (-1 != (c = getopt_long(argc, argv, "a:b:B:c:CE:F:G:hi:I:m:M:n:o:p:P:Qr:RsS:t:vT", long_options, &opt_index))) {
        switch (c) {
        case 'b':
            bgpfile = optarg;
            break;
        case 'B':
            poisson = strtol(optarg, &endptr, 10);
            break;
        case 'C':
            coarse = true;
            break;
        case 'c':
            count = strtol(optarg, &endptr, 10);
            break;
        case 'F':
            fillmode = strtol(optarg, &endptr, 10);
            break;
        case 'i':
            inlist = optarg;
            break;
        case 's':
            random_scan = false;
            break;
        case 'S':
            seed = strtol(optarg, &endptr, 10);
            break;
        case 'T':
            testing = true;
            break;
        case 'Q':
            entire = true;
            break;
        case 'n':
            ttl_neighborhood = strtol(optarg, &endptr, 10);
            break;
        case 'v':
            verbosity++;
            break;
        case 'o':
            output = optarg;
            break;
        case 'p':
            dstport = strtol(optarg, &endptr, 10);
            break;
        case 'E':
            instance = strtol(optarg, &endptr, 10);
            break;
        case 'P':
            probesrc = optarg;
            receive = false;
            break;
        case 'R':
            probe = false;
            break;
        case 'm':
            maxttl = strtol(optarg, &endptr, 10);
            break;
        case 'r':
            rate = strtol(optarg, &endptr, 10);
            break;
        case 'I':
            int_name = optarg;
            break;
        case 'G':
            dstmac = read_mac(optarg);
            break;
        case 'M':
            srcmac = read_mac(optarg);
            break;
        case 'a':
            srcaddr = read_v6_src_addr(optarg);
            break;
        case 't':
            if (strcmp(optarg, "ICMP6") == 0) {
                ipv6 = true;
                type = TR_ICMP6;
            } else if(strcmp(optarg, "UDP6") == 0) {
                ipv6 = true;
                type = TR_UDP6;
            } else if(strcmp(optarg, "TCP6_SYN") == 0) {
                ipv6 = true;
                type = TR_TCP6_SYN;
            } else if(strcmp(optarg, "TCP6_ACK") == 0) {
                ipv6 = true;
                type = TR_TCP6_ACK;
            } else if(strcmp(optarg, "ICMP") == 0) {
                type = TR_ICMP;
            } else if(strcmp(optarg, "ICMP_REPLY") == 0) {
                type = TR_ICMP_REPLY;
            } else if(strcmp(optarg, "UDP") == 0) {
                type = TR_UDP;
            } else if(strcmp(optarg, "TCP_SYN") == 0) {
                type = TR_TCP_SYN;
            } else {
                usage(argv[0]);
            }
            break;
        case 'h':
        default:
            debug(OFF, ">> yarrp v" << VERSION);
            debug(OFF, ">> https://www.cmand.org/yarrp/");
            usage(argv[0]);
        }
    }
    /* set default output file, if not set */
    if (not output) {
        output = (char *) malloc(UINT8_MAX);
        snprintf(output, UINT8_MAX, "output.yrp");
    }
    /* set default destination port based on tracetype, if not set */
    if (not dstport) {
        dstport = 80;
        if ( (type == TR_UDP) || (type == TR_UDP6) )
            dstport = 53;
    }
    debug(LOW, ">> yarrp v" << VERSION);
}

void
YarrpConfig::usage(char *prog) {
    cout << "Usage: " << prog << " [OPTIONS] [targets]" << endl
    << "OPTIONS:" << endl
    << "  -i, --input             Input target file" << endl
    << "  -o, --output            Output file (default: output.yrp)" << endl
    << "  -c, --count             Probes to issue (default: unlimited)" << endl
    << "  -t, --type              Probe type: ICMP, ICMP_REPLY, TCP_SYN, TCP_ACK, UDP," << endl
    << "                                      ICMP6, UDP6, TCP6_SYN, TCP6_ACK (default: TCP_ACK)" << endl
    << "  -r, --rate              Scan rate in pps (default: 10)" << endl
    << "  -m, --maxttl            Maximum TTL (for ip input list only)" << endl
    << "  -v, --verbose           verbose (default: off)" << endl
    << "  -F, --fillmode          Fill mode maxttl (default: 0)" << endl
    << "  -s, --sequential        Scan sequentially (default: random)" << endl
    << "  -n, --neighborhood      Neighborhood TTL (default: 0)" << endl
    << "  -b, --bgp               BGP table (default: none)" << endl
    << "  -S, --seed              Seed (default: random)" << endl
    << "  -p, --port              Transport dst port (default: 80)" << endl
    << "  -E, --instance          Prober instance (default: 0)" << endl
    << "  -T, --test              Don't send probes (default: off)" << endl
    << "  -Q, --entire            Entire IPv4/IPv6 Internet (default: off)" << endl
    << "  -I, --interface         Network interface (required for IPv6)" << endl
    << "  -a, --srcaddr           IPv6 address of probing host (default: auto)" << endl
    << "  -G, --dstmac            MAC of gateway router (default: auto)" << endl
    << "  -M, --srcmac            MAC of probing host (default: auto)" << endl
    << "  -h, --help              Show this message" << endl
/* Undocumented options */
//    << "  -C, --coarse            Coarse ms timestamps (default: us)" << endl
//    << "  -B, --poisson           Poisson TTLs (default: uniform)" << endl
//    << "  -P, --probeonly         Probe only, don't receive" << endl
//    << "  -R, --receiveonly       Receive only, don't probe" << endl
    << "Targets:" << endl
    << "  List of IPv4 or IPv6 prefixes." << endl
    << "    Example: 192.168.1.0/24" << endl
    << "             2602:306:8b92:b000::/47" << endl
    << endl;
    exit(-1);
}
