/****************************************************************************
   Program:     $Id: trace.cpp 39 2015-12-30 20:28:36Z rbeverly $
   Date:        $Date: 2015-12-30 12:28:36 -0800 (Wed, 30 Dec 2015) $
   Description: traceroute class
****************************************************************************/
#include "yarrp.h"

Traceroute6::Traceroute6(YarrpConfig *_config, Stats *_stats) : Traceroute(_config, _stats) {
    memset(&source6, 0, sizeof(struct sockaddr_in6));
    if (config->probesrc) {
        source6.sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, config->probesrc, &source6.sin6_addr) != 1)
          fatal("** Bad source address."); 
    } else if (config->srcaddr != NULL) {
         source6.sin6_addr = *config->srcaddr;
    } else {
        infer_my_ip6(&source6);
    }
#ifdef _LINUX
    sndsock = raw_sock6(&source6);
#else
    /* Init BPF socket */
    sndsock = bpfget();
    if (sndsock < 0) fatal("bpf open error\n");
    struct ifreq bound_if;
    strcpy(bound_if.ifr_name, config->int_name);
    if (ioctl(sndsock, BIOCSETIF, &bound_if) > 0) fatal("ioctl err\n");
#endif
    pcount = 0;

    assert(config);
    assert(config->srcmac);

    /* Set Ethernet header */
    frame = (uint8_t *)calloc(1, PKTSIZE);
    memcpy (frame, config->dstmac, 6 * sizeof (uint8_t));
    memcpy (frame + 6, config->srcmac, 6 * sizeof (uint8_t));
    frame[12] = 0x86; /* IPv6 Ethertype */
    frame[13] = 0xdd;

    /* Set static IP6 header fields */
    outip = (struct ip6_hdr *) (frame + ETH_HDRLEN);
    outip->ip6_flow = htonl(0x6<<28|tc<<20|flow);
    outip->ip6_src = source6.sin6_addr;

    /* Init yarrp payload struct */
    payload = (struct ypayload *)malloc(sizeof(struct ypayload));
    payload->id = htonl(0x79727036);
    payload->instance = config->instance;

    if (config->probe and config->receive) {
        /* Open output ytr file */
        if (config->output)
            openOutput();
        pthread_create(&recv_thread, NULL, listener6, this);
        /* give listener thread time to startup */
        sleep(1);
    }
}

Traceroute6::~Traceroute6() {
    free(frame);
}

void Traceroute6::probePrint(struct in6_addr addr, int ttl) {
    uint32_t diff = elapsed();
    inet_ntop(AF_INET6, &source6.sin6_addr, addrstr, INET6_ADDRSTRLEN);
    if (config->probesrc)
        cout << addrstr << " -> ";
    //inet_ntop(AF_INET6, &(outip->ip6_dst), addrstr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &addr, addrstr, INET6_ADDRSTRLEN);
    cout << addrstr << " ttl: " << ttl << " t=" << diff;
    (config->coarse) ? cout << "ms" << endl : cout << "us" << endl;
}

void
Traceroute6::probe(struct in6_addr addr, int ttl) {
#ifdef _LINUX 
    struct sockaddr_ll target;
    memset(&target, 0, sizeof(target));
    target.sll_ifindex = if_nametoindex(config->int_name);
    target.sll_family = AF_PACKET;
    memcpy(target.sll_addr, config->srcmac, 6 * sizeof(uint8_t));
    target.sll_halen = 6;
    probe(&target, addr, ttl);
#else
    probe(NULL, addr, ttl);
#endif
}

void
Traceroute6::probe(void *target, struct in6_addr addr, int ttl) {
    outip->ip6_hlim = ttl;
    outip->ip6_dst = addr;

    uint16_t transport_hdr_len = 0;
    switch(tr_type) {
      case TR_ICMP6:
        outip->ip6_nxt = IPPROTO_ICMPV6;
        transport_hdr_len = sizeof(struct icmp6_hdr);
        break;
      case TR_UDP6:
        outip->ip6_nxt = IPPROTO_UDP;
        transport_hdr_len = sizeof(struct udphdr);
        break;
      case TR_TCP6_SYN:
      case TR_TCP6_ACK:
        outip->ip6_nxt = IPPROTO_TCP;
        transport_hdr_len = sizeof(struct tcphdr);
        break;
      default:
        cerr << "** bad trace type" << endl;
        assert(false);
    } 

    /* Populate a yarrp payload */
    payload->ttl = ttl;
    payload->fudge = 0;
    uint32_t diff = elapsed();
    payload->diff = diff;
    u_char *data = (u_char *)(frame + ETH_HDRLEN + sizeof(ip6_hdr) 
                              + transport_hdr_len);
    memcpy(data, payload, sizeof(struct ypayload));

    /* Populate transport header */
    packlen = transport_hdr_len + sizeof(struct ypayload);
    make_transport();
    /* Copy yarrp payload again, after changing fudge for cksum */
    memcpy(data, payload, sizeof(struct ypayload));
    outip->ip6_plen = htons(packlen);

    /* xmit frame */
    if (verbosity > HIGH) {
      cout << ">> " << Tr_Type_String[tr_type] << " probe: ";
      probePrint(addr, ttl);
    }
    uint16_t framelen = ETH_HDRLEN + sizeof(ip6_hdr) + packlen;
#ifdef _LINUX
    if (sendto(sndsock, frame, framelen, 0, (struct sockaddr *)target,
        sizeof(struct sockaddr_ll)) < 0)
    {
        fatal("%s: error: %s", __func__, strerror(errno));
    }
#else
    /* use the BPF to send */
    write(sndsock, frame, framelen);
#endif
    pcount++;
}

void 
Traceroute6::make_transport() {
    void *transport = frame + ETH_HDRLEN + sizeof(ip6_hdr);
    uint16_t sum = in_cksum((unsigned short *)&(outip->ip6_dst), 16);
    if (tr_type == TR_ICMP6) {
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)transport;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_cksum = 0;
        icmp6->icmp6_id = htons(sum);
        icmp6->icmp6_seq = htons(pcount);
        icmp6->icmp6_cksum = p_cksum(outip, (u_short *) icmp6, packlen);
    } else if (tr_type == TR_UDP6) {
        struct udphdr *udp = (struct udphdr *)transport;
        udp->uh_sport = htons(sum);
        udp->uh_dport = htons(dstport);
        udp->uh_ulen = htons(packlen);
        udp->uh_sum = 0;
        udp->uh_sum = p_cksum(outip, (u_short *) udp, packlen);
        /* set checksum for paris goodness */
        uint16_t crafted_cksum = htons(0xbeef);
        payload->fudge = compute_data(udp->uh_sum, crafted_cksum);
        udp->uh_sum = crafted_cksum;
    } else if (tr_type == TR_TCP6_SYN || tr_type == TR_TCP6_ACK) {
        struct tcphdr *tcp = (struct tcphdr *)transport;
        tcp->th_sport = htons(sum);
        tcp->th_dport = htons(dstport);
        tcp->th_seq = htonl(1);
        tcp->th_off = 5;
        tcp->th_win = htons(65535);
        tcp->th_sum = 0;
        tcp->th_x2 = 0;
        tcp->th_flags = 0;
        tcp->th_urp = htons(0);
        if (tr_type == TR_TCP6_SYN) 
           tcp->th_flags |= TH_SYN; 
        else
           tcp->th_flags |= TH_ACK; 
        tcp->th_sum = p_cksum(outip, (u_short *) tcp, packlen);
        /* set checksum for paris goodness */
        uint16_t crafted_cksum = htons(0xbeef);
        payload->fudge = compute_data(tcp->th_sum, crafted_cksum);
        tcp->th_sum = crafted_cksum;
    }
}

void
Traceroute6::openOutput() {
    inet_ntop(AF_INET6, &(getSource()->sin6_addr), addrstr, INET6_ADDRSTRLEN);
    Traceroute::openOutput(addrstr);
}
