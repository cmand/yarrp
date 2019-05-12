/****************************************************************************
   Program:     $Id: trace.cpp 39 2015-12-30 20:28:36Z rbeverly $
   Date:        $Date: 2015-12-30 12:28:36 -0800 (Wed, 30 Dec 2015) $
   Description: traceroute class
****************************************************************************/
#include "yarrp.h"

Traceroute::Traceroute(YarrpConfig *_config, Stats *_stats) : config(_config), stats(_stats), tree(NULL)
{
    tr_type = (traceroute_type) config->type; 
    dstport = config->dstport;
    if (config->ttl_neighborhood)
      initHisto(config->ttl_neighborhood);
    gettimeofday(&start, NULL);
    debug(HIGH, ">> Traceroute engine started: " << start.tv_sec);
}

Traceroute::~Traceroute() {
    gettimeofday(&start, NULL);
    debug(HIGH, ">> Traceroute engine stopped: " << start.tv_sec);
    fflush(NULL);
    pthread_cancel(recv_thread);
    if (out)
        fclose(out);
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
Traceroute::openOutput(const char *src) {
    debug(DEBUG, ">> Output: " << config->output);
    if ( (config->output)[0] == '-')
      out = stdout;
    else
      out = fopen(config->output, "a");
    if (out == NULL)
        fatal("%s: %s", __func__, strerror(errno));
#ifdef GITREV
    fprintf(out, "# yarrp v%s (%s)\n", VERSION, GITREV);
#else
    fprintf(out, "# yarrp v%s\n", VERSION);
#endif
    fprintf(out, "# Started: %s", ctime(&(start.tv_sec)));
    fprintf(out, "# Source: %s\n", src);
    fprintf(out, "# Trace type: %s (%d)\n", Tr_Type_String[tr_type], tr_type);
    fprintf(out, "# Rate: %u pps\n", config->rate);
    if (config->inlist) 
        fprintf(out, "# Target file: %s\n", config->inlist);
    else if (config->entire)
        fprintf(out, "# Targets: entire\n");
    fprintf(out, "# Probing: Random: %d Seed: %d\n",
        config->random_scan, config->seed);
    fprintf(out, "# TTL control: Max: %d Fill: %d Poisson: %d Nbrhood: %d\n",
        config->maxttl, config->fillmode, config->poisson, config->ttl_neighborhood);
    if (config->bgpfile)
        fprintf(out, "# BGP table: %s\n", config->bgpfile);
    if (config->coarse)
        fprintf(out, "# RTT granularity: ms\n");
    else
        fprintf(out, "# RTT granularity: us\n");
    fprintf(out, "# target, sec, usec, type, code, ttl, hop, rtt, ipid, psize, rsize, rttl, rtos, count\n");
}
