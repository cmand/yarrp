/****************************************************************************
   Program:     $Id: $
   Date:        $Date: $
   Description: subnet list 
****************************************************************************/

#ifndef SUBNET_LIST_H
#define SUBNET_LIST_H
#include <stdint.h>
#include <string>
#include <list>

#include "subnet.h"

using namespace std;

class SubnetList {
    public:
        SubnetList(uint8_t maxttl, uint8_t gran);
        virtual ~SubnetList();
        virtual void add_subnet(string s, bool ipv6);
        virtual uint32_t next_address(struct in_addr *in, uint8_t *ttl);
        virtual uint32_t next_address(struct in6_addr *in, uint8_t *ttl);
        uint32_t count();

    protected:
        list<Subnet> subnets;
        list<Subnet6> subnets6;
        uint32_t addr_count;
        uint8_t maxttl;
        uint8_t granularity;
        uint32_t ttlmask_bits;
        uint32_t ttlmask;

        uint16_t getHost(uint8_t *addr);

    private:
        list<Subnet>::iterator current_subnet;
        list<Subnet6>::iterator current_subnet6;
        uint32_t current_twentyfour; 
        uint32_t current_48; 
        uint8_t current_ttl; 
};

#endif /* SUBNET_LIST_H */
