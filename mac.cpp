/****************************************************************************
   Program:     $Id: net.cpp 14 2014-12-30 02:33:44Z laalt $
   Date:        $Date: 2014-12-29 18:33:44 -0800 (Mon, 29 Dec 2014) $
   Description: networking routines
****************************************************************************/
#include "yarrp.h"

char *LLResolv::mac2str(char *mac) {
    static char buf[BUFSIZE];
    snprintf(buf, BUFSIZE, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

int LLResolv::print_gw() {
    char buf[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &(gw.ip), buf, INET6_ADDRSTRLEN) == NULL)
        return -1;
    printf("IPv4 gateway: %s\n", buf);
    printf("IPv4 gateway mac: %s\n", mac2str(gw.mac));
    if (inet_ntop(AF_INET6, &(gw.ip6), buf, INET6_ADDRSTRLEN) == NULL)
        return -1;
    printf("IPv6 gateway: %s\n", buf);
    printf("IPv6 gateway mac: %s\n", mac2str(gw.mac6));
    return 0;
}

void LLResolv::setDstMAC(uint8_t **mac) {
    *mac = (uint8_t *)calloc(6, sizeof(uint8_t)); 
    memcpy(*mac, gw.mac6, ETH_ALEN); 
}
 
#ifdef _LINUX
void LLResolv::mine(const char *interface) {
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        printf("PF_PACKET error: %s\n", strerror(errno));
        exit(-1);
    }
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    ioctl (sock, SIOCGIFHWADDR, &ifr);
    close(sock);
}
#else
void LLResolv::mine(const char *interface) {};
#endif

#ifdef _LINUX
void LLResolv::gateway() {
    char buf[BUFSIZE];

    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) <= 0) {
        printf("PF_NETLINK error: %s\n", strerror(errno));
        exit(-1);
    }
    size_t nlseq = send_req(buf, nlseq, RTM_GETROUTE);
    size_t msg_len = read_res(buf, nlseq);
    struct nlmsghdr *nlmsg = reinterpret_cast<struct nlmsghdr *>(buf);
    for (; NLMSG_OK(nlmsg, msg_len); nlmsg = NLMSG_NEXT(nlmsg, msg_len))
        parse_route(nlmsg);
    nlseq = send_req(buf, nlseq, RTM_GETNEIGH);
    msg_len = read_res(buf, nlseq);
    nlmsg = reinterpret_cast<struct nlmsghdr *>(buf);
    for (; NLMSG_OK(nlmsg, msg_len); nlmsg = NLMSG_NEXT(nlmsg, msg_len))
        parse_neigh(nlmsg);
    close(sock);
}
#else
void LLResolv::gateway() {
    fatal("Non-linux IPv6 requires specifying source (-M) and gateway (-G) MAC");
};
#endif

#ifdef _LINUX
void LLResolv::setSrcMAC(uint8_t **mac) {
    *mac = (uint8_t *)calloc(6, sizeof(uint8_t)); 
    memcpy(*mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN); 
}
void LLResolv::print_self() {
    printf("Host mac: %s\n", mac2str(ifr.ifr_hwaddr.sa_data));
} 
#else
void LLResolv::setSrcMAC(uint8_t **mac) {};
void LLResolv::print_self() {};
#endif

#ifdef _LINUX
int LLResolv::send_req(char *buf, size_t nlseq, size_t req_type) {
    memset(buf, 0, BUFSIZE);
    struct nlmsghdr * nlmsg = reinterpret_cast<struct nlmsghdr *>(buf);
    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlmsg->nlmsg_type = req_type;
    nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlmsg->nlmsg_seq = nlseq++;
    nlmsg->nlmsg_pid = getpid();

    if (send(sock, buf, nlmsg->nlmsg_len, 0) < 0)
        return -1;

    return nlseq;
}

int LLResolv::read_res(char *buf, size_t nlseq) {
    struct nlmsghdr *nlmsg;
    int len;
    size_t total_len = 0;

    do {
        if ((len = recv(sock, buf, BUFSIZE - total_len, 0)) < 0)
            return -1;

        nlmsg = reinterpret_cast<struct nlmsghdr *>(buf);

        if (NLMSG_OK(nlmsg, len) == 0)
            return -1;
        if (nlmsg->nlmsg_type == NLMSG_ERROR)
            return -1;
        if (nlmsg->nlmsg_type == NLMSG_DONE)
            break;

        buf += len;
        total_len += len;

        if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
            break;

    } while (nlmsg->nlmsg_seq != nlseq || nlmsg->nlmsg_pid != getpid());

    return total_len;
}

void LLResolv::parse_route(struct nlmsghdr *nlmsg) {
    struct gw_info *info = &gw;

    struct rtmsg *rtmsg = reinterpret_cast<struct rtmsg *>(NLMSG_DATA(nlmsg));
    if (rtmsg->rtm_table != RT_TABLE_MAIN)
        return;

    struct rtattr *attr = reinterpret_cast<struct rtattr *>(RTM_RTA(rtmsg));
    size_t len = RTM_PAYLOAD(nlmsg);

    for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type != RTA_GATEWAY)
            continue;
        if (rtmsg->rtm_family == AF_INET) 
            info->ip = *reinterpret_cast<uint32_t *>(RTA_DATA(attr));
        else if (rtmsg->rtm_family == AF_INET6) 
            memcpy(info->ip6, RTA_DATA(attr), IPV6SIZE);
        break;
    }
}

void LLResolv::parse_neigh(struct nlmsghdr *nlmsg) {
    char mac[ETH_ALEN];
    uint32_t ip = 0;
    char ip6[IPV6SIZE];
    struct gw_info *info = &gw;

    struct ndmsg *ndmsg = reinterpret_cast<struct ndmsg *>(NLMSG_DATA(nlmsg));
    struct rtattr *attr = reinterpret_cast<struct rtattr *>(RTM_RTA(ndmsg));
    size_t len = RTM_PAYLOAD(nlmsg);

    for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type == NDA_LLADDR) 
            memcpy(mac, RTA_DATA(attr), ETH_ALEN);

        if (ndmsg->ndm_family == AF_INET && attr->rta_type == NDA_DST)
            ip = *reinterpret_cast<uint32_t *>(RTA_DATA(attr));

        if (ndmsg->ndm_family == AF_INET6 && attr->rta_type == NDA_DST)
            memcpy(ip6, RTA_DATA(attr), IPV6SIZE);
    }

    if (ndmsg->ndm_family == AF_INET && ip && ip == info->ip)
        memcpy(info->mac, mac, ETH_ALEN);

    if (ndmsg->ndm_family == AF_INET6) {
        if (memcmp(ip6, info->ip6, IPV6SIZE) == 0)
           memcpy(info->mac6, mac, ETH_ALEN);
    }
}
#endif
