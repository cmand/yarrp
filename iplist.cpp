#include "yarrp.h"
#include "random_list.h"

IPList::IPList(uint8_t _maxttl, bool _rand) {
  perm = NULL;
  permsize = 0;
  maxttl = _maxttl;
  ttlbits = intlog(maxttl);
  ttlmask = 0xffffffff >> (32 - ttlbits);
  rand = _rand;
  memset(key, 0, KEYLEN);
  //std::cout << ">> MAXTTL: " << int(maxttl) << " TTLBits: " << int(ttlbits) << std::endl;
  //printf("ttlmask: %02x\n", ttlmask);
}

void IPList::setkey(int seed) {
    debug(HIGH, ">> Randomizing, seed: " << seed);
    permseed(key, seed);
}

IPList4::~IPList4() {
  targets.clear();
  cperm_destroy(perm);
}

IPList6::~IPList6() {
  targets.clear();
  cperm_destroy(perm);
}

/* seed */
void IPList4::seed() {
  PermMode mode = PERM_MODE_CYCLE;
  assert(targets.size() > 0);
  permsize = targets.size() * maxttl;
  if (permsize < 1000000) 
    mode = PERM_MODE_PREFIX;
  perm = cperm_create(permsize, mode, PERM_CIPHER_RC5, key, 16);
  assert(perm);
}

void IPList6::seed() {
  PermMode mode = PERM_MODE_PREFIX;
  assert(targets.size() > 0);
  permsize = targets.size() * maxttl;
  if (permsize > 5000000) {
    mode = PERM_MODE_CYCLE;
    std::cout << ">> Warning: reduced IPv6 performance with this many targets" <<  std::endl;
    std::cout << ">>          use fewer targets, or lower max TTL (-m)" <<  std::endl;
  }
  perm = cperm_create(permsize, mode, PERM_CIPHER_SPECK, key, 8);
  assert(perm);
}

/* Read list of input IPs */
void IPList4::read(char *in) {
  std::ifstream inlist(in);
  if (inlist.good() == false)
    fatal("** Bad input file: %s", in);
  std::string line;
  struct in_addr addr;
  while (getline(inlist, line)) {
    if (!line.empty() && line[line.size() - 1] == '\r')
      line.erase( std::remove(line.begin(), line.end(), '\r'), line.end() );
    if (inet_aton(line.c_str(), &addr) != 1)
      fatal("** Couldn't parse IPv4 address: %s", line.c_str());
    targets.push_back(addr.s_addr);
  }
  if (permsize == 0)
    seed();
  debug(LOW, ">> IPv4 targets: " << targets.size());
}

/* Read list of input IPs */
void IPList6::read(char *in) {
  std::ifstream inlist(in);
  if (inlist.good() == false)
    fatal("Bad input file: %s", in);
  std::string line;
  struct in6_addr addr;
  while (getline(inlist, line)) {
    if (!line.empty() && line[line.size() - 1] == '\r')
      line.erase( std::remove(line.begin(), line.end(), '\r'), line.end() );
    if (inet_pton(AF_INET6, line.c_str(), &addr) != 1)
      fatal("** Couldn't parse IPv6 address: %s", line.c_str());
    targets.push_back(addr);
  }  
  if (permsize == 0)
    seed();
  debug(LOW, ">> IPv6 targets: " << targets.size());
}

uint32_t IPList4::next_address(struct in_addr *in, uint8_t * ttl) {
  if (rand) 
    return next_address_rand(in, ttl);
  else
    return next_address_seq(in, ttl);
}

/* sequential next address */
uint32_t IPList4::next_address_seq(struct in_addr *in, uint8_t * ttl) {
  static std::vector<uint32_t>::iterator iter = targets.begin();
  static uint32_t last_addr = *iter;
  static uint8_t  last_ttl = 0;

  if (last_ttl + 1 > maxttl) {
    iter++;
    if (iter == targets.end())
      return 0;
    last_ttl = 0;
    last_addr = *(iter);
  }
  last_ttl+=1;
  *ttl = last_ttl;
  in->s_addr = last_addr;
  return 1;
}

/* random next address */
uint32_t IPList4::next_address_rand(struct in_addr *in, uint8_t * ttl) {
  static uint32_t next = 0;

  if (permsize == 0)
    seed();

  if (PERM_END == cperm_next(perm, &next))
    return 0;

  in->s_addr = targets[next >> ttlbits];
  if (ttlbits == 0)
    *ttl = 1;
  else
    *ttl = (next & ttlmask)  + 1;
  return 1;
}

uint32_t IPList6::next_address(struct in6_addr *in, uint8_t * ttl) {
  if (rand) 
    return next_address_rand(in, ttl);
  else
    return next_address_seq(in, ttl);
}

/* sequential next address */
uint32_t IPList6::next_address_seq(struct in6_addr *in, uint8_t * ttl) {
  static std::vector<struct in6_addr>::iterator iter = targets.begin();
  static struct in6_addr last_addr = *iter;
  static uint8_t  last_ttl = 0;
  int i;

  if (last_ttl + 1 > maxttl) {
    iter++;
    if (iter == targets.end())
      return 0;
    last_ttl = 0;
    last_addr = *(iter);
  }
  last_ttl+=1;
  *ttl = last_ttl;
  for(i = 0; i < 16; i++)
    in->s6_addr[i] = last_addr.s6_addr[i];
  return 1;
}

/* random next address */
uint32_t IPList6::next_address_rand(struct in6_addr *in, uint8_t * ttl) {
  static uint32_t next = 0;

  if (permsize == 0)
    seed();

  if (PERM_END == cperm_next(perm, &next))
    return 0;

  *in = targets[next >> ttlbits];
  *ttl = (next & ttlmask)  + 1;
  return 1;
}
