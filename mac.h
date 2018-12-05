/****************************************************************************
   Program:     $Id: net.cpp 14 2014-12-30 02:33:44Z laalt $
   Date:        $Date: 2014-12-29 18:33:44 -0800 (Mon, 29 Dec 2014) $
   Description: networking routines
****************************************************************************/
#include "yarrp.h"

#ifdef _LINUX
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif
#include <sys/ioctl.h>
#include <net/if.h>

#define BUFSIZE 8192
#define IPV6SIZE 16
#ifndef ETH_ALEN
 #define ETH_ALEN 6
#endif

struct gw_info {
    uint32_t ip;
    char ip6[IPV6SIZE];
    char mac[ETH_ALEN];
    char mac6[ETH_ALEN];
};

class LLResolv {
    public:
    LLResolv() {};

    char *mac2str(char *mac);
    void mine(const char *interface);
    void gateway();
    int print_gw();
    void print_self();
    void setSrcMAC(uint8_t **mac);
    void setDstMAC(uint8_t **mac);

    private:
    struct gw_info gw;
    struct ifreq ifr; /* Linux netdevice(7) */
    int sock;

    int send_req(char *buf, size_t nlseq, size_t req_type);
    int read_res(char *buf, size_t nlseq);
    void parse_route(struct nlmsghdr *nlmsg);
    void parse_neigh(struct nlmsghdr *nlmsg);
};
