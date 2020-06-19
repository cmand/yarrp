/****************************************************************************
   Program:     $Id: listener.cpp 40 2016-01-02 18:54:39Z rbeverly $
   Date:        $Date: 2016-01-02 10:54:39 -0800 (Sat, 02 Jan 2016) $
   Description: yarrp listener thread
****************************************************************************/
#include "yarrp.h"

ICMP::ICMP() : 
   rtt(0), ttl(0), type(0), code(0), length(0), quote_p(0), sport(0), dport(0), ipid(0),
   probesize(0), replysize(0), replyttl(0), replytos(0)
{
    gettimeofday(&tv, NULL);
    mpls_stack = NULL;
}

ICMP4::ICMP4(struct ip *ip, struct icmp *icmp, uint32_t elapsed, bool _coarse): ICMP()
{
    coarse = _coarse;
    memset(&ip_src, 0, sizeof(struct in_addr));
    type = (uint8_t) icmp->icmp_type;
    code = (uint8_t) icmp->icmp_code;

    ip_src = ip->ip_src;
#ifdef _BSD
    replysize = ip->ip_len;
#else
    replysize = ntohs(ip->ip_len);
#endif
    ipid = ntohs(ip->ip_id);
    replytos = ip->ip_tos;
    replyttl = ip->ip_ttl;
    unsigned char *ptr = NULL;

    quote = NULL;
    if (((type == ICMP_TIMXCEED) and (code == ICMP_TIMXCEED_INTRANS)) or
        (type == ICMP_UNREACH)) {
        ptr = (unsigned char *) icmp;
        quote = (struct ip *) (ptr + 8);
        quote_p = quote->ip_p;
#ifdef _BSD
        probesize = quote->ip_len;
#else
        probesize = ntohs(quote->ip_len);
#endif
        ttl = (ntohs(quote->ip_id)) & 0xFF;
        instance = (ntohs(quote->ip_id) >> 8) & 0xFF;

        /* Original probe was TCP */
        if (quote->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *) (ptr + 8 + (quote->ip_hl << 2));
            rtt = elapsed - ntohl(tcp->th_seq);
            if (elapsed < ntohl(tcp->th_seq))
                cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << ntohl(tcp->th_seq) << endl;
            sport = ntohs(tcp->th_sport);
            dport = ntohs(tcp->th_dport);
        }

        /* Original probe was UDP */
        else if (quote->ip_p == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *) (ptr + 8 + (quote->ip_hl << 2));
            /* recover timestamp from UDP.check and UDP.payloadlen */
            int payloadlen = ntohs(udp->uh_ulen) - sizeof(struct icmp);
            int timestamp = udp->uh_sum;
            sport = ntohs(udp->uh_sport);
            dport = ntohs(udp->uh_dport);
            if (payloadlen > 2)
                timestamp += (payloadlen-2) << 16;
            if (elapsed >= timestamp) {
                rtt = elapsed - timestamp;
            /* checksum was 0x0000 and because of RFC, 0xFFFF was transmitted
             * causing us to see packet as being 65 (2^{16}/1000) seconds in future */
            } else if (udp->uh_sum == 0xffff) {
                timestamp = (payloadlen-2) << 16;
                rtt = elapsed - timestamp;
            }
            if (elapsed < timestamp) {
                cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << timestamp << endl;
                sport = dport = 0;
            }
        } 

        /* Original probe was ICMP */
        else if (quote->ip_p == IPPROTO_ICMP) {
            struct icmp *icmp = (struct icmp *) (ptr + 8 + (quote->ip_hl << 2));
            uint32_t timestamp = ntohs(icmp->icmp_id);
            timestamp += ntohs(icmp->icmp_seq) << 16;
            rtt = elapsed - timestamp;
            sport = icmp->icmp_cksum;
        }

        /* According to Malone PAM 2007, 2% of replies have bad IP dst. */
        uint16_t sum = in_cksum((unsigned short *)&(quote->ip_dst), 4);
        if (sport != sum) {
            cerr << "** IP dst in ICMP reply quote invalid!" << endl;
            sport = dport = 0;
        }

        /* Finally, does this ICMP packet have an extension (RFC4884)? */
        length = (ntohl(icmp->icmp_void) & 0x00FF0000) >> 16;
        length *= 4;
        if ( (length > 0) and (replysize > length+8) ) {
            //printf("*** ICMP Extension %d/%d\n", length, replysize);
            ptr = (unsigned char *) icmp;
            ptr += length+8;
            if (length < 128) 
                ptr += (128-length);
            // ptr at start of ICMP extension
            ptr += 4;
            // ptr at start of MPLS stack header
            ptr += 2;
            // is this a class/type 1/1 (MPLS)?
            if ( (*ptr == 0x01) and (*(ptr+1) == 0x01) ) {
                ptr += 2;
                uint32_t *tmp;
                mpls_label_t *lse = (mpls_label_t *) calloc(1, sizeof(mpls_label_t) );
                mpls_stack = lse;
                for (int labels = 0; labels < MAX_MPLS_STACK_HEIGHT; labels++) {
                    tmp = (uint32_t *) ptr;
                    if (labels > 0) {
                        mpls_label_t *nextlse = (mpls_label_t *) calloc(1, sizeof(mpls_label_t) );
                        lse->next = nextlse;
                        lse = nextlse;
                    }
                    lse->label = (htonl(*tmp) & 0xFFFFF000) >> 12;
                    lse->exp   = (htonl(*tmp) & 0x00000F00) >> 8;
                    lse->ttl   = (htonl(*tmp) & 0x000000FF);
                    // bottom of stack?
                    if (lse->exp & 0x01) 
                        break;
                    ptr+=4;
                }
            }
        }
    }
}

/**
 * Create ICMP6 object on received response.
 *
 * @param ip   Received IPv6 hdr
 * @param icmp Received ICMP6 hdr
 * @param elapsed Total running time
 */
ICMP6::ICMP6(struct ip6_hdr *ip, struct icmp6_hdr *icmp, uint32_t elapsed, bool _coarse) : ICMP()
{
    is_yarrp = false;
    coarse = _coarse;
    memset(&ip_src, 0, sizeof(struct in6_addr));
    type = (uint8_t) icmp->icmp6_type;
    code = (uint8_t) icmp->icmp6_code;
    ip_src = ip->ip6_src;
    replysize = ntohs(ip->ip6_plen);
    replyttl = ip->ip6_hlim;

    /* Ethernet
     * IPv6 hdr
     * ICMP6 hdr                struct icmp6_hdr *icmp;         <- ptr
     *  IPv6 hdr                struct ip6_hdr *icmpip;
     *  Ext hdr                 struct ip6_ext *eh; (if present)
     *  Probe transport hdr     struct tcphdr,udphdr,icmp6_hdr; 
     *  Yarrp payload           struct ypayload *qpayload;
     */

    unsigned char *ptr = (unsigned char *) icmp; 
    quote = (struct ip6_hdr *) (ptr + sizeof(struct icmp6_hdr));            /* Quoted IPv6 hdr */
    struct ip6_ext *eh = NULL;                /* Pointer to any extension header */
    struct ypayload *qpayload = NULL;     /* Quoted ICMPv6 yrp payload */ 
    uint16_t ext_hdr_len = 0;
    quote_p = quote->ip6_nxt;
    int offset = 0;

    if (icmp->icmp6_type == ICMP6_ECHO_REPLY) {
        qpayload = (struct ypayload *) (ptr + sizeof(struct icmp6_hdr));
    } else {
        // handle frag EH
        if (quote_p == 44) {
            eh = (struct ip6_ext *) (ptr + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) );
            ext_hdr_len = 8;
            quote_p = eh->ip6e_nxt;
        }

        // continue processing
        offset = sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + ext_hdr_len;
        if (quote_p == IPPROTO_TCP) {
            qpayload = (struct ypayload *) (ptr + offset + sizeof(struct tcphdr));
        } else if (quote_p == IPPROTO_UDP) {
            qpayload = (struct ypayload *) (ptr + offset + sizeof(struct udphdr));
        } else if (quote_p == IPPROTO_ICMPV6) {
            qpayload = (struct ypayload *) (ptr + offset + sizeof(struct icmp6_hdr));
        } else {
            warn("unknown quote\n");
            return;
        }
    }

    if (ntohl(qpayload->id) == 0x79727036) 
        is_yarrp = true;
    ttl = qpayload->ttl;
    instance = qpayload->instance;
    yarrp_target = &(qpayload->target);
    uint32_t diff = qpayload->diff;
    if (elapsed >= diff)
        rtt = elapsed - diff;
    else
        cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << diff << endl;

    /* ICMP6 echo replies only quote the yarrp payload, not the full packet! */
    if (((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) or
        (type == ICMP6_DST_UNREACH)) {
        probesize = ntohs(quote->ip6_plen);
        if (quote_p == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *) (ptr + offset);
            sport = ntohs(tcp->th_sport);
            dport = ntohs(tcp->th_dport);
        } else if (quote_p == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *) (ptr + offset);
            sport = ntohs(udp->uh_sport);
            dport = ntohs(udp->uh_dport);
        } else if (quote_p == IPPROTO_ICMPV6) {
            struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) (ptr + offset);
            sport = ntohs(icmp6->icmp6_id);
            dport = ntohs(icmp6->icmp6_seq);
        }
        uint16_t sum = in_cksum((unsigned short *)&(quote->ip6_dst), 16);
        if (sport != sum) {
            cerr << "** IP6 dst in ICMP6 reply quote invalid!" << endl;
            sport = dport = 0;
        }
    }
}

uint32_t ICMP4::quoteDst() {
    if ((type == ICMP_TIMXCEED) and (code == ICMP_TIMXCEED_INTRANS)) {
        return quote->ip_dst.s_addr;
    }
    return 0;
}

void ICMP::printterse(char *src) {
    float r = 0.0;
    coarse ? r = rtt/1.0 : r = rtt/1000.0;
    printf(">> ICMP response: %s Type: %d Code: %d TTL: %d RTT: %2.3fms",
      src, type, code, ttl, r);
    if (instance)
      printf(" Inst: %u", instance);
    printf("\n");
}

void ICMP::print(char *src, char *dst, int sum) {
    printf("\ttype: %d code: %d from: %s\n", type, code, src);
    printf("\tYarrp instance: %u\n", instance);
    printf("\tTS: %lu.%ld\n", tv.tv_sec, (long) tv.tv_usec);
    if (coarse)
      printf("\tRTT: %u ms\n", rtt);
    else
      printf("\tRTT: %u us\n", rtt);
    printf("\tProbe dst: %s\n", dst);
    printf("\tProbe TTL: %d\n", ttl);
    if (ipid) printf("\tReply IPID: %d\n", ipid);
    if (quote_p) printf("\tQuoted Protocol: %d\n", quote_p);
    if ( (quote_p == IPPROTO_TCP) || (quote_p == IPPROTO_UDP) ) 
      printf("\tProbe TCP/UDP src/dst port: %d/%d\n", sport, dport);
    if ( (quote_p == IPPROTO_ICMP) || (quote_p == IPPROTO_ICMPV6) )
      printf("\tQuoted ICMP checksum: %d\n", sport);
    if (sum) printf("\tCksum of probe dst: %d\n", sum);
}


char *
ICMP::getMPLS() {
    static char *mpls_label_string = (char *) calloc(1, PKTSIZE);
    static char *label = (char *) calloc(1, PKTSIZE);
    memset(mpls_label_string, 0, PKTSIZE);
    memset(label, 0, PKTSIZE);
    mpls_label_t *head = mpls_stack;
    if (not head)
        snprintf(mpls_label_string, PKTSIZE, "0");
    while (head) {
        //printf("**** LABEL: %d TTL: %d\n", head->label, head->ttl);
        if (head->next)
            snprintf(label, PKTSIZE, "%d:%d,", head->label, head->ttl);
        else
            snprintf(label, PKTSIZE, "%d:%d", head->label, head->ttl);
        strcat(mpls_label_string, label);
        head = head->next;
    }
    return mpls_label_string;
}

void 
ICMP4::print() {
    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_src, src, INET_ADDRSTRLEN);
    char dst[INET_ADDRSTRLEN] = "no-quote";
    uint16_t sum = 0;
    if (quote) {
        inet_ntop(AF_INET, &(quote->ip_dst), dst, INET_ADDRSTRLEN);
        sum = in_cksum((unsigned short *)&(quote->ip_dst), 4);
    }
    if (verbosity > HIGH) {
        printf(">> ICMP response:\n");
        ICMP::print(src, dst, sum);
        if (mpls_stack)
            printf("\t MPLS: [%s]\n", getMPLS());
    } else if (verbosity > LOW) {
        ICMP::printterse(src);
    }
}

void
ICMP6::print() {
    char src[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip_src, src, INET6_ADDRSTRLEN);
    char dst[INET6_ADDRSTRLEN] = "no-quote";
    uint16_t sum = 0;
    if (quote != NULL) {
        inet_ntop(AF_INET6, &(quote->ip6_dst), dst, INET6_ADDRSTRLEN);
        sum = in_cksum((unsigned short *)&(quote->ip6_dst), 16);
    }
    if (verbosity > HIGH) {
        printf(">> ICMP6 response:\n");
        ICMP::print(src, dst, sum);
    } else if (verbosity > LOW) {
        ICMP::printterse(src);
    }
}

/* trgt, sec, usec, type, code, ttl, hop, rtt, ipid, psize, rsize, rttl, rtos */
void ICMP::write(FILE ** out, uint32_t count, char *src, char *target) {
    if (*out == NULL)
        return;
    fprintf(*out, "%s %lu %ld %d %d ",
        target, tv.tv_sec, (long) tv.tv_usec, type, code);
    fprintf(*out, "%d %s %d %u ",
        ttl, src, rtt, ipid);
    fprintf(*out, "%d %d %d %d ",
        probesize, replysize, replyttl, replytos);
    fprintf(*out, "%s ", getMPLS());
    fprintf(*out, "%d\n", count);
}

void ICMP4::write(FILE ** out, uint32_t count) {
    if ((sport == 0) and (dport == 0))
        return;
    char src[INET_ADDRSTRLEN];
    char target[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(quote->ip_dst), target, INET_ADDRSTRLEN);
    ICMP::write(out, count, src, target);
}

void ICMP6::write(FILE ** out, uint32_t count) {
    char src[INET6_ADDRSTRLEN];
    char target[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip_src, src, INET6_ADDRSTRLEN);
    if (((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) or
    (type == ICMP6_DST_UNREACH)) { 
        inet_ntop(AF_INET6, &(quote->ip6_dst.s6_addr), target, INET6_ADDRSTRLEN);
    } 
    /* In the case of an ECHO REPLY, the quote does not contain the invoking
     * packet, so we rely on the target as encoded in the yarrp payload */
    else if (type == ICMP6_ECHO_REPLY) {
        inet_ntop(AF_INET6, yarrp_target, target, INET6_ADDRSTRLEN);
    } 
    /* If we don't know what else to do, assume that source of the packet
     * was the target */
    else {
        inet_ntop(AF_INET6, &ip_src, target, INET6_ADDRSTRLEN);
    }
    ICMP::write(out, count, src, target);
}

struct in6_addr ICMP6::quoteDst6() {
    if ((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) {
        return quote->ip6_dst;
    }
    struct in6_addr a;
    memset(&a, 0, sizeof(struct in6_addr));
    return a;
}
