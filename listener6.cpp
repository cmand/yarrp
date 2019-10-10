/****************************************************************************
   Program:     $Id: listener.cpp 40 2016-01-02 18:54:39Z rbeverly $
   Date:        $Date: 2016-01-02 10:54:39 -0800 (Sat, 02 Jan 2016) $
   Description: yarrp listener thread
****************************************************************************/
#include "yarrp.h"
#include <signal.h>

static volatile bool run = true;
void intHandler(int dummy);

#ifndef _LINUX
int bpfinit(char *dev, size_t *bpflen) {
    int rcvsock = -1;

    debug(DEVELOP, ">> Listener6 BPF");
    rcvsock = bpfget();
    if (rcvsock < 0) fatal("bpf open error\n");
    struct ifreq bound_if;
    strcpy(bound_if.ifr_name, dev);
    if (ioctl(rcvsock, BIOCSETIF, &bound_if) > 0) fatal("ioctl err\n");
    uint32_t enable = 1;
    if (ioctl(rcvsock, BIOCSHDRCMPLT, &enable) <0) fatal("ioctl err\n");
    if (ioctl(rcvsock, BIOCIMMEDIATE, &enable) <0) fatal("ioctl err\n");
    struct bpf_program fcode = {0};
    struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IPV6, 0, 3),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 20),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_ICMPV6, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };
    fcode.bf_len = sizeof(insns) / sizeof(struct bpf_insn);
    fcode.bf_insns = &insns[0];
    if(ioctl(rcvsock, BIOCSETF, &fcode) < 0) fatal("set filter\n");
    ioctl(rcvsock, BIOCGBLEN, bpflen);
    return rcvsock;
}
#endif

void *listener6(void *args) {
    fd_set rfds;
    Traceroute6 *trace = reinterpret_cast < Traceroute6 * >(args);
    struct timeval timeout;
    unsigned char *buf = (unsigned char *) calloc(1,PKTSIZE);
    uint32_t nullreads = 0;
    int n, len;
    TTLHisto *ttlhisto = NULL;
    uint32_t elapsed = 0;
    struct ip6_hdr *ip = NULL;                /* IPv6 hdr */
    struct icmp6_hdr *ippayload = NULL;       /* ICMP6 hdr */
    struct ip6_hdr *icmpip = NULL;            /* Quoted IPv6 hdr */
    struct ypayload *quotepayload = NULL;     /* Quoted ICMPv6 yrp payload */ 
    int rcvsock;                              /* receive (icmp) socket file descriptor */

    /* block until main thread says we're ready. */
    trace->lock(); 
    trace->unlock(); 

#ifdef _LINUX
    if ((rcvsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        cerr << "yarrp listener socket error:" << strerror(errno) << endl;
    }
#else
    /* Init BPF */
    size_t blen = 0;
    rcvsock = bpfinit(trace->config->int_name, &blen);
    unsigned char *bpfbuf = (unsigned char *) calloc(1,blen);
    struct bpf_hdr *bh = NULL;
#endif

    signal(SIGINT, intHandler);
    while (true and run) {
        if (nullreads >= MAXNULLREADS)
            break;
#ifdef _LINUX
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(rcvsock, &rfds);
        n = select(rcvsock + 1, &rfds, NULL, NULL, &timeout);
        if (n == 0) {
            nullreads++;
            cerr << ">> Listener: timeout " << nullreads;
            cerr << "/" << MAXNULLREADS << endl;
            continue;
        }
	if (n == -1) {
            fatal("select error");
        }
        nullreads = 0;
        len = recv(rcvsock, buf, PKTSIZE, 0); 
#else
        len = read(rcvsock, bpfbuf, blen);
	unsigned char *p = bpfbuf;
reloop:
        bh = (struct bpf_hdr *)p;
	buf = p + bh->bh_hdrlen;  /* realign buf */
#endif
        if (len == -1) {
            fatal("%s %s", __func__, strerror(errno));
        }
        ip = (struct ip6_hdr *)(buf + ETH_HDRLEN);
        quotepayload = NULL;
        if (ip->ip6_nxt == IPPROTO_ICMPV6) {
            ippayload = (struct icmp6_hdr *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr)];
            if (ippayload->icmp6_type == ICMP6_ECHO_REPLY) {
                quotepayload = (struct ypayload *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)];
            } else {
                icmpip = (struct ip6_hdr *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)];
                if (icmpip->ip6_nxt == IPPROTO_TCP) {
                    quotepayload = (struct ypayload *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)];
                } else if (icmpip->ip6_nxt == IPPROTO_UDP) {
                    quotepayload = (struct ypayload *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct udphdr)];
                } else if (icmpip->ip6_nxt == IPPROTO_ICMPV6) {
                    quotepayload = (struct ypayload *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)];
                } else {
                    continue;
                }
            }
            elapsed = trace->elapsed();
            if ((ippayload->icmp6_type != ICMP6_ECHO_REQUEST) and (ntohl(quotepayload->id) == 0x79727036)) {
                ICMP *icmp = new ICMP6(ip, ippayload, quotepayload, elapsed, trace->config->coarse);
                if (verbosity > LOW)
                    icmp->print();
                /* Fill mode logic. */
                if (trace->config->fillmode) {
                    if ( (icmp->getTTL() >= trace->config->maxttl) and
                         (icmp->getTTL() < trace->config->fillmode) ) {
                        trace->stats->fills+=1;
                        trace->probe(icmp->quoteDst6(), icmp->getTTL() + 1); 
                    }
                }
                icmp->write(&(trace->config->out), trace->stats->count);
                /* TTL tree histogram */
                if (trace->ttlhisto.size() > icmp->quoteTTL()) {
                    ttlhisto = trace->ttlhisto[icmp->quoteTTL()];
                    ttlhisto->add(icmp->getSrc6(), elapsed);
                }
                if (verbosity > DEBUG)
                    trace->dumpHisto();
                delete icmp;
            }
        } 
#ifndef _LINUX
	p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
	if (p < bpfbuf + len) goto reloop;
#endif
    }
    return NULL;
}
