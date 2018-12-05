/****************************************************************************
   Program:     $Id: listener.cpp 40 2016-01-02 18:54:39Z rbeverly $
   Date:        $Date: 2016-01-02 10:54:39 -0800 (Sat, 02 Jan 2016) $
   Description: yarrp listener thread
****************************************************************************/
#include "yarrp.h"
#include <signal.h>

static volatile bool run = true;

void intHandler(int dummy) {
    run = false;
}

void           *
listener(void *args) {
    fd_set rfds;
    Traceroute *trace = reinterpret_cast < Traceroute * >(args);
    struct timeval timeout;
    unsigned char buf[PKTSIZE];
    uint32_t nullreads = 0;
    int n, len;
    TTLHisto *ttlhisto = NULL;
    uint32_t elapsed = 0;
    struct ip *ip = NULL;
    struct icmp *ippayload = NULL;
    int rcvsock; /* receive (icmp) socket file descriptor */

    if ((rcvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        cout << "yarrp listener socket error:" << strerror(errno) << endl;
    }

    while (true) {
        if (nullreads >= MAXNULLREADS)
            break;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(rcvsock, &rfds);
        n = select(rcvsock + 1, &rfds, NULL, NULL, &timeout);
        /* only timeout if we're also probing (not listen-only mode) */
        if ((n == 0) and (trace->config->probe)) {
            nullreads++;
            cout << ">> Listener: timeout " << nullreads;
            cout << "/" << MAXNULLREADS << endl;
            continue;
        }
        if (n > 0) {
            nullreads = 0;
            len = recv(rcvsock, buf, PKTSIZE, 0);
            if (len == -1) {
                cerr << ">> Listener: read error: " << strerror(errno) << endl;
                continue;
            }
            ip = (struct ip *)buf;
            if ((ip->ip_v == IPVERSION) and (ip->ip_p == IPPROTO_ICMP)) {
                ippayload = (struct icmp *)&buf[ip->ip_hl << 2];
                elapsed = trace->elapsed();
                ICMP *icmp = new ICMP4(ip, ippayload, elapsed, trace->config->coarse);
                if (verbosity > LOW) 
                    icmp->print();
                /* ICMP message not from this yarrp instance, skip. */
                if (icmp->getInstance() != trace->config->instance) {
                    delete icmp;
                    continue;
                }
                if (icmp->getSport() == 0)
                    trace->stats->baddst+=1;
                /* Fill mode logic. */
                if (trace->config->fillmode) {
                    if ( (icmp->getTTL() >= trace->config->maxttl) and
                         (icmp->getTTL() < trace->config->fillmode) ) {
                        trace->stats->fills+=1;
                        trace->probe(icmp->quoteDst(), icmp->getTTL() + 1); 
                    }
                }
                icmp->write(&(trace->out), trace->stats->count);
                Status *status = NULL;
                if (trace->tree != NULL) 
                    status = (Status *) trace->tree->get(icmp->quoteDst());
                if (status) {
                    status->result(icmp->quoteTTL(), elapsed);
                    //status->print();
                }
                /* TTL tree histogram */
                if (trace->ttlhisto.size() > icmp->quoteTTL()) {
                    /* make certain we received a valid reply before adding  */
                    if ( (icmp->getSport() != 0) and 
                         (icmp->getDport() != 0) ) 
                    {
                        ttlhisto = trace->ttlhisto[icmp->quoteTTL()];
                        ttlhisto->add(icmp->getSrc(), elapsed);
                    }
                }
                if (verbosity > DEBUG) 
                    trace->dumpHisto();
                delete icmp;
            }
        }
    }
    return NULL;
}
