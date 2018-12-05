#ifndef SUBNET_H
#define SUBNET_H

#include <stdint.h>
#include <string>

class Subnet {
    public:
    Subnet(std::string s);
    ~Subnet();

    uint32_t first();
    uint32_t last();
    uint32_t count();

    private:
    uint32_t start;
    uint32_t end;
    uint32_t offset;
    uint8_t  smask;
};

class Subnet6 {
    public:
    Subnet6(std::string s);
    ~Subnet6();
    uint64_t count() {
        return cnt;
    }
    struct in6_addr *first();

    private:
    struct in6_addr start;
    struct in6_addr end;
    struct in6_addr offset;
    uint8_t smask;
    uint64_t cnt;
};

#endif                          /* SUBNET_H */
