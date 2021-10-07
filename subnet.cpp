#include "yarrp.h"
#include "subnet.h"

static uint32_t NETMASKS[] = {
        0x00000000,
        0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
        0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
        0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
        0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
        0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
        0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
        0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
        0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff
};

Subnet::Subnet(string s) {
    uint32_t addr;
    uint8_t mask;
    char *p = strdup(s.c_str());

    if (2 == sscanf(s.c_str(), "%[0-9.]/%hhu", p, &mask)) {
        addr = ntohl(inet_addr(p));
        if (mask > 32) {
            start = end = offset = 0;
            fatal("Bad IPv4 subnet mask: %s", s.c_str());
        }
        start = addr & NETMASKS[mask];
        smask = mask;
        offset = 0;
        end = start + (1 << (32 - mask));
    } else {
        fatal("Error parsing IPv4 subnet: %s", s.c_str());
    }
    free(p);
}

Subnet6::Subnet6(string s, uint8_t granularity) {
    uint8_t m;
    char *p = strdup(s.c_str());
    if (2 == sscanf(s.c_str(), "%[a-fA-F0-9:]/%hhu", p, &m)) {
        //cout << "Got IPv6 prefix: " << p << " mask: " << int (m) << endl;
        if (inet_pton(AF_INET6, p, &start) != 1) {
            fatal("Error parsing IPv6 address: %s", p);
        }
        smask = m;
        if (smask > 64) {
            fatal("IPv6 prefix must be at least /64 or larger!");
        }
        cnt = 1 << (granularity-m);

        /* four 32-bits words in ipv6 address; which one is subnet boundary */
        uint8_t boundary_word = m / 32;
        uint8_t boundary_mask = m % 32;
        char output[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &start, output, INET6_ADDRSTRLEN); 
        //cout << "Start: " << output << endl; 
        //cout << "boundary word:" << (int) boundary_word << endl;
        //cout << "boundary mask:" << (int) boundary_mask << endl;
        for (int i=boundary_word+1; i<4; i++ ) {
           start.s6_addr32[i] = 0;
        }
        //printf("WORD: %08x\n", ntohl(start.s6_addr32[boundary_word]));
        //printf("MASK: %08x\n", NETMASKS[boundary_mask]);
        start.s6_addr32[boundary_word] = htonl( ntohl(start.s6_addr32[boundary_word]) & NETMASKS[boundary_mask] );
        //printf("WORD: %08x\n", ntohl(start.s6_addr32[boundary_word]));
        inet_ntop(AF_INET6, &start, output, INET6_ADDRSTRLEN); 
        //cout << "Start: " << output << endl; 

        memcpy(&end, &start, sizeof(struct in6_addr));
        for (int i=boundary_word+1; i<4; i++ ) {
          end.s6_addr32[i] += NETMASKS[32];
        }
        end.s6_addr32[boundary_word] += htonl( (1 << (32-boundary_mask))-1);
        inet_ntop(AF_INET6, &end, output, INET6_ADDRSTRLEN); 
        //cout << "End: " << output << endl; 
    } else {
        fatal("Error parsing IPv6 subnet: %s", s.c_str());
    }
    free(p);
}

Subnet::~Subnet() {
}

Subnet6::~Subnet6() {
}

uint32_t Subnet::first() {
    return start;
}

struct in6_addr *Subnet6::first() {
    return &start;
}

uint32_t Subnet::last() {
    return end - 1;
}

/* we iterate through /24's.  so, count is number of /24s */
uint32_t Subnet::count() {
    return (end - start) >> 8;
}
