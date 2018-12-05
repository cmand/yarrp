#include "yarrp.h"
#include "random_list.h"

RandomSubnetList::RandomSubnetList(uint8_t _maxttl):SubnetList(_maxttl) {
    seeded = false;
    perm = NULL;
}

RandomSubnetList::~RandomSubnetList() {
    if (perm)
        cperm_destroy(perm);
}

void            
RandomSubnetList::seed() {
    uint8_t buffer[16];
    PermMode mode = PERM_MODE_CYCLE;

    if (addr_count < 500000) {
        mode = PERM_MODE_PREFIX;
    }
    //printf("%s: permsize: %d\n", __func__, addr_count);
    perm = cperm_create(addr_count, mode, PERM_CIPHER_RC5, buffer, 16);
    if (!perm) {
        printf("Failed to initialize permutation of size %u. Code: %d\n", addr_count, cperm_get_last_error());
        exit(1);
    }
    seeded = true;
}

uint32_t        
RandomSubnetList::next_address(struct in_addr *in, uint8_t *ttl) {
    list < Subnet >::iterator iter;
    uint32_t next, subnet_count, current = 0;
    uint32_t addr, offset;

    if (!seeded)
        seed();

    if (PERM_END == cperm_next(perm, &next))
        return 0;

    for (iter = subnets.begin(); iter != subnets.end(); iter++) {
        subnet_count = (*iter).count() * maxttl;
        if (next >= current && next < current + subnet_count) {
            offset = next - current;
            // LSB's encode the TTL
            *ttl = (offset & ttlmask) + 1;
            addr = (*iter).first() + (offset << (8 - ttlmask_bits));
            addr = addr & 0xffffff00;
            addr += getHost((uint8_t *) &addr);
            in->s_addr = htonl(addr);
            return 1;
        }
        current += subnet_count;
    }
    return 1;
}

uint32_t        
RandomSubnetList::next_address(struct in6_addr *in, uint8_t * ttl) {
    list < Subnet6 >::iterator iter;
    uint32_t next, subnet_count, current = 0;
    uint32_t offset;
    char output[INET6_ADDRSTRLEN];

    if (!seeded)
        seed();

    if (PERM_END == cperm_next(perm, &next))
        return 0;

    for (iter = subnets6.begin(); iter != subnets6.end(); iter++) {
        subnet_count = (*iter).count() * maxttl;
        if (next >= current && next < current + subnet_count) {
            offset = next - current;
            *ttl = (offset & ttlmask) + 1;
            // upper bits are offset into subnet
            int subnetoffset = (offset >> ttlmask_bits);
            //cout << "Subnetoffset: " << subnetoffset << endl;
            int word0 = subnetoffset / 65536;
            int word1 = subnetoffset % 65536;
              
            //struct in6_addr *in = (*iter).first(); 
            memcpy(in, (*iter).first(), sizeof(struct in6_addr));
            inet_ntop(AF_INET6, in, output, INET6_ADDRSTRLEN); 
            //cout << "Using first: " << output << endl; 

            (*in).s6_addr32[0] += htonl(word0);
            (*in).s6_addr32[1] += htonl(word1<<16);
            (*in).s6_addr32[3] += htonl(getHost((uint8_t *)in));

            inet_ntop(AF_INET6, in, output, INET6_ADDRSTRLEN); 
            //cout << "Using: " << output << endl; 
            return 1;
        }
        current += subnet_count;
    }
    return 1;
}

uint16_t        
RandomSubnetList::getHost(uint8_t *addr) {
    uint16_t sum = addr[0] + addr[1] + addr[2] + addr[3] + 127;
    return sum & 0xff;
}
