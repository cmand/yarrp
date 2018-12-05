/****************************************************************************
   Program:     $Id: net.cpp 14 2014-12-30 02:33:44Z laalt $
   Date:        $Date: 2014-12-29 18:33:44 -0800 (Mon, 29 Dec 2014) $
   Description: networking routines
****************************************************************************/
#include "yarrp.h"

/**
 * Prints a range of data in hex.
 *
 * @param buf Start of the data range
 * @param len Length of the data range
 * @param brk Number of bytes to print per line
 * @param tabs Number of tabs to insert at the beginning of each new line
 */
void 
print_binary(const unsigned char *buf, int len, int brk, int tabs) {
    int i, j;
    for (i = 0; i < len; i++) {
        if ((i > 0) && (i % brk == 0)) {
            printf("\n");
            for (j = 0; j < tabs; j++)
                printf("\t");
        }
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

/**
 * Prints each header (net, trnspt, data) of a packet in hex.
 *
 * @param packet Start of the buffer containing the packet
 * @param tot_len Total length of the packet buffer
 */
void 
print_packet(const unsigned char *packet, int tot_len) {
    struct ip *ip;
    struct tcphdr *tcp;
    int iph_len, tcph_len, hdrs_len;

    ip = (struct ip *)packet;
    iph_len = ip->ip_hl << 2;

    tcp = (struct tcphdr *)(packet + iph_len);
    tcph_len = tcp->th_off << 2;

    hdrs_len = iph_len + tcph_len;

    printf("\tIP Header:\t");
    print_binary((unsigned char *)ip, iph_len, 10, 3);

    printf("\tTCP Header:\t");
    print_binary((unsigned char *)tcp, tcph_len, 10, 3);

    /* only print a data header if the packet has data */
    if (tot_len > hdrs_len) {
        printf("\tData:\t\t");
        print_binary(packet + hdrs_len, tot_len - hdrs_len, 10, 3);
    }
}

/**
 * Create a new raw IPv4 socket.
 *
 * @param sin_orig Source port and address family (only used on PlanetLab)
 * @return Descriptor for the newly created socket
 */
int 
raw_sock(struct sockaddr_in *sin_orig) {
    int sock, one = 1;
    struct sockaddr_in sin;

    /* create a new sin without the address */
    memset(&sin, 0, sizeof sin);
    sin.sin_family = sin_orig->sin_family;
    sin.sin_port = sin_orig->sin_port;

    /* establish raw socket */
    if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
        fatal("Create socket failed: %s", strerror(errno));

    if (setsockopt(sock, 0, IP_HDRINCL, &one, sizeof one) < 0)
        warn("setsockopt failed: %s", strerror(errno));

    return sock;
}

/**
 * Determine our public-facing IPv4 address.
 *
 * @param mei Where to save the address we find
 * @return 1 for success, -1 for failure
 */
int 
infer_my_ip(struct sockaddr_in *mei) {
    struct sockaddr_in me, serv;
    socklen_t len = sizeof me;
    int sock, err;

    memset(&serv, 0, sizeof serv);
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
        return -1;

    err = connect(sock, (const struct sockaddr *)&serv, sizeof serv);
    if (err == -1)
        return -1;

    err = getsockname(sock, (struct sockaddr *)&me, &len);
    if (err == -1)
        return -1;

    mei->sin_addr = me.sin_addr;
    return 1;
}

/**
 * Determine our public-facing IPv6 address.
 *
 * @param mei6 Where to save the address we find
 * @return 1 for success, -1 for failure
 */
int
infer_my_ip6(struct sockaddr_in6 *mei6) {
    struct sockaddr_in6 me6, serv6;
    socklen_t len = sizeof me6;
    int sock6, err;

    memset(&serv6, 0, sizeof serv6);
    serv6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "2001:4860:4860::8888", 
              &serv6.sin6_addr.s6_addr);
    serv6.sin6_port = htons(53);

    sock6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock6 == -1)
        return -1;

    err = connect(sock6, (const struct sockaddr *)&serv6, sizeof serv6);
    if (err == -1)
        return -1;

    err = getsockname(sock6, (struct sockaddr *)&me6, &len);
    if (err == -1)
        return -1;

    mei6->sin6_addr = me6.sin6_addr;
    return 1;
}

/**
 * Lookup the given address in DNS.
 *
 * @param url DNS or IPv4 address in string form
 * @param target Where to save the IPv4 address we find
 */
void 
resolve_target_ip(char *url, struct sockaddr_in *target) {
    int error;
    struct addrinfo hints, *result;

    /* hints allows us to tell getaddrinfo what kind of answer we want */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;  /* we want IPv4 addresses only */

    /*
     * we use getaddrinfo() because it can handle either DNS addresses or IPs
     * as strings
     */
    error = getaddrinfo(url, NULL, &hints, &result);
    if (error)
        fatal("Error in getaddrinfo: %s", gai_strerror(error));

    /* just grab the first address in the linked list */
    target->sin_addr = ((struct sockaddr_in *)result->ai_addr)->sin_addr;

    freeaddrinfo(result);
}

/**
 * Compute an IP checksum.
 *
 * @param addr Start of the data range
 * @param len Length of the data range
 * @return 2-byte long IP checksum value
 */
unsigned short 
in_cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the carry
     * bits from the top 16 bits into the lower 16 bits.
     */
    assert(addr);
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* 4mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }
    /* 4add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return answer;
}

/*
 * struct ipovly seems to be a BSD only item... Defining it here for now, but
 * there should be a better, more cross-platform way of doing this.
 */
#ifndef _BSD
struct ipovly {
    u_char          ih_x1;
    u_char          ih_pr;
    u_short         ih_len;
    struct in_addr  ih_src;
    struct in_addr  ih_dst;
};
#endif

struct ip6ovly {
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
    uint32_t        ip6_len;
    u_char          ip6_zeros[3];
    u_char          ip6_pr; 
};

/*
 * Checksum routine for UDP and TCP headers.
 */
u_short
p_cksum(struct ip *ip, u_short * data, int len) {
    static struct ipovly ipo;
    u_short sumh, sumd;
    u_long sumt;

    ipo.ih_pr = ip->ip_p;
    ipo.ih_len = htons(len);
    ipo.ih_src = ip->ip_src;
    ipo.ih_dst = ip->ip_dst;

    sumh = in_cksum((u_short *) & ipo, sizeof(ipo));    /* pseudo ip hdr cksum */
    sumd = in_cksum((u_short *) data, len);     /* payload data cksum */
    sumt = (sumh << 16) | (sumd);

    return ~in_cksum((u_short *) & sumt, sizeof(sumt));
}

/*
 * IPv6 checksum routine for UDP/TCP/ICMP (Section 8.1 of RFC 2460).
 */
u_short
p_cksum(struct ip6_hdr *ip6, u_short * data, int len) {
    static struct ip6ovly ipo;
    u_short sumh, sumd;
    u_long sumt;

    ipo.ip6_pr = ip6->ip6_nxt;
    ipo.ip6_len = htons(len);
    ipo.ip6_src = ip6->ip6_src;
    ipo.ip6_dst = ip6->ip6_dst;

    sumh = in_cksum((u_short *) & ipo, sizeof(ipo));    /* pseudo ip hdr cksum */
    sumd = in_cksum((u_short *) data, len);     /* payload data cksum */
    sumt = (sumh << 16) | (sumd);

    return ~in_cksum((u_short *) & sumt, sizeof(sumt));
}

/* 
 * Compute packet payload needed to make UDP checksum correct
 * (Used to ensure Paris-style load balancing
 */
unsigned short compute_data(unsigned short start_cksum, unsigned short target_cksum) {
    unsigned short answer = 0x0000;
    /* per RFC, if computed checksum is 0, the value 0xFFFF is transmitted */
    if (target_cksum == 0xFFFF)
        target_cksum = 0x0000;
    /* if the ones' complement of the target checksum is greater than
     * the ones' complement of the starting checksum, use the overflow
     * in the computation of IP/UDP checksum to keep result positive
     */
    if (~target_cksum > ~start_cksum)
        answer = ~target_cksum - (~start_cksum);
    else
        answer = 0xFFFF - (~start_cksum) + (~target_cksum); 
    return answer;
}

/* @@ RB: Gaston v6 code only supports Linux */
#ifdef _LINUX
/**
 * Create a new raw IPv6 socket.
 *
 * @param sin_orig Source port and address family
 * @return Descriptor for the newly created socket
 */
int
raw_sock6(struct sockaddr_in6 *sin6_orig) {
    int sock, one = 1;
    struct sockaddr_in6 sin6;

    /* create a new sin without the address */
    memset(&sin6, 0, sizeof sin6);
    sin6.sin6_family = sin6_orig->sin6_family;
    sin6.sin6_port = sin6_orig->sin6_port;

    /* establish raw socket */
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        fatal("Create socket failed: %s", strerror(errno));

    return sock;
}
#endif

/* BPF dev finder/opener */
int bpfget() {
  char dev[32];
  int fd = -1;
  for (int i=0; i < 255; i++) {
    snprintf(dev, sizeof(dev), "/dev/bpf%u", i);
    //printf("trying to open %s\n", dev);
    fd = open(dev, O_RDWR);
    if (fd > -1) return fd;
    switch (errno) {
      case EBUSY:
        break;
      default:
        return -1;
    }
  }
  errno = ENOENT;
  return -1;
}
