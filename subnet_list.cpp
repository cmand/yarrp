#include "yarrp.h"
#include "subnet_list.h"

SubnetList::SubnetList(uint8_t _maxttl) : maxttl(_maxttl) {
    addr_count = 0;
    current_twentyfour = 0;
    current_48 = 0;
    current_ttl = 0;
    ttlmask_bits = intlog(maxttl);
    ttlmask = (1 << ttlmask_bits) - 1;
};

SubnetList::~SubnetList() {
};

void            
SubnetList::add_subnet(string s, bool ipv6) {
    if (ipv6) {
        Subnet6 subnet = Subnet6(s);
        subnets6.push_back(subnet);
        current_subnet6 = subnets6.begin();
        addr_count += subnet.count() * maxttl;
    } else {
        Subnet subnet = Subnet(s);
        subnets.push_back(subnet);
        current_subnet = subnets.begin();
        addr_count += subnet.count() * maxttl;
    }
}

uint32_t
SubnetList::next_address(struct in6_addr *in, uint8_t * ttl) {
    if (current_subnet6 == subnets6.end()) {
        return 0;
    }
    *ttl = current_ttl;

    // don't muck w/ the iterator; copy 
    memcpy(in, current_subnet6->first(), sizeof(struct in6_addr));

    /* since we're dividing in /48s:
        - increment second word's high 16 bits by current_48
        - only increment first word (32bits) if we overflow current_48 16 bits
    */
    int word0 = current_48 / 65536;
    int word1 = current_48 % 65536;

    (*in).s6_addr32[0] += htonl(word0);
    (*in).s6_addr32[1] += htonl(word1<<16);
    (*in).s6_addr32[3] += htonl(getHost(0));
    /*
    char output[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, in, output, INET6_ADDRSTRLEN); 
    cout << "Start: " << output << endl; 
    */
    if (++current_ttl > maxttl) {
        current_ttl = 0;
        current_48 += 1;
    }
    if (current_48 >= (*current_subnet6).count()) {
        current_48 = 0;
        current_subnet6++;
    }
    return 1;
} 

uint32_t
SubnetList::next_address(struct in_addr *in, uint8_t * ttl) {
    if (current_subnet == subnets.end()) {
        return 0;
    }
    in->s_addr = htonl((*current_subnet).first() + (current_twentyfour << 8) + getHost(0));
    *ttl = current_ttl;
    if (++current_ttl > maxttl) {
        current_ttl = 0;
        current_twentyfour += 1;
    }
    if (current_twentyfour >= (*current_subnet).count()) {
        current_twentyfour = 0;
        current_subnet++;
    }
    return 1;
}

uint32_t
SubnetList::count() {
    return addr_count;
}

uint16_t        
SubnetList::getHost(uint8_t * addr) {
    return 1;
}
