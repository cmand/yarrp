/****************************************************************************
   Program:     $Id: trace.cpp 39 2015-12-30 20:28:36Z rbeverly $
   Date:        $Date: 2015-12-30 12:28:36 -0800 (Wed, 30 Dec 2015) $
   Description: traceroute class
****************************************************************************/
#include "yarrp.h"

Traceroute::Traceroute(YarrpConfig *_config, Stats *_stats) : config(_config), stats(_stats), tree(NULL), recv_thread()
{
    dstport = config->dstport;
    if (config->ttl_neighborhood)
      initHisto(config->ttl_neighborhood);
    gettimeofday(&start, NULL);
    debug(HIGH, ">> Traceroute engine started: " << start.tv_sec);
    // RFC2822 timestring
    struct tm *p = localtime(&(start.tv_sec));
    char s[1000];
    strftime(s, 1000, "%a, %d %b %Y %T %z", p);
    config->set("Start", s, true);
    pthread_mutex_init(&recv_lock, NULL);
}

Traceroute::~Traceroute() {
    gettimeofday(&start, NULL);
    debug(HIGH, ">> Traceroute engine stopped: " << start.tv_sec);
    fflush(NULL);
    pthread_cancel(recv_thread);
    if (config->out)
        fclose(config->out);
}

void
Traceroute::initHisto(uint8_t ttl) {
    cout << ">> Init TTL histogram for neighborhood: " << int(ttl) << endl;
    for (int i = 0; i <= ttl; i++) {
        TTLHisto *t = NULL;
        if (config->ipv6)
            t = new TTLHisto6();
        else
            t = new TTLHisto4();
        ttlhisto.push_back(t);
    }
}

void
Traceroute::dumpHisto() {
    if (ttlhisto.size() == 0) 
        return;
    cout << ">> Dumping TTL Histogram:" << endl;
    for (int i = 1; i < ttlhisto.size(); i++) {
        TTLHisto *t = ttlhisto[i];
        cout << "\tTTL: " << i << " ";
        t->dump();
    }
}

uint32_t
Traceroute::elapsed() {
    gettimeofday(&now, NULL);
    if (config->coarse)
        return tsdiff(&now, &start);
    return tsdiffus(&now, &start); 
}

void
Traceroute::lock() {
    pthread_mutex_lock(&recv_lock);
}

void
Traceroute::unlock() {
    pthread_mutex_unlock(&recv_lock);
}
