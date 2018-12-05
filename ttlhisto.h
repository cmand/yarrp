/* TTL tree histogram; last time we've seen a new interface
 * at a given TTL 
 */
#ifndef _TTLHISTO_H_
#define _TTLHISTO_H_

#include <unordered_set>

class TTLHisto {
    public:
    TTLHisto() : lastNew(0), lastSent(0), probes(0), prob_thresh(0.05) {};
    void probed(uint32_t elapsed) {
        lastSent = elapsed;
    }
    /* If no new interface seen in past 5 minutes, we 
     * stop probing at this TTL */
    bool shouldProbe() {
        int32_t delta = lastSent - lastNew; 
        if (delta > 30*1000) {
            //std::cout << "* Not probing TTL b/c TTL > 300*1000" << std::endl;
            return false;
        }
        return true;
    }
    virtual bool add(uint32_t src, uint32_t elapsed) { return false; };
    virtual bool add(in6_addr *src, uint32_t elapsed) { return false; };
    virtual bool shouldProbeProb() { return false; };
    virtual void dump() = 0;

    protected:
    uint32_t lastNew;
    uint32_t lastSent;
    uint32_t probes;
    float prob_thresh;
    float prob;
};

class TTLHisto4 : public TTLHisto {
    public:
    TTLHisto4() {};
    void dump() {
        int32_t delta = lastSent - lastNew;
        std::cout << "Last new intf seen: " << lastNew << " sent: " << lastSent;
        std::cout << " delta: " << delta << std::endl;
        for (std::unordered_set<uint32_t>::iterator iter = routers.begin();
             iter != routers.end();
             iter++) 
        {
            struct in_addr sin;
            sin.s_addr = *iter;
            std::cout << "\t\t" << inet_ntoa(sin) << std::endl;
        }
    }
    bool add(uint32_t src, uint32_t elapsed) {
        probes++;
        if (routers.find(src) == routers.end()) {
            probes = routers.size() + 1; /* reset probes to parity */
            routers.insert(src);
            lastNew = elapsed;
            return true;
        }
        return false;
    }
    bool shouldProbeProb() {
        prob = (float) routers.size() / probes;
        if (prob < prob_thresh)
          return false;
        return true;
    }

    private:
	std::unordered_set<uint32_t> routers;
};

class TTLHisto6 : public TTLHisto {
    public:
    TTLHisto6() {
        source = (char *) calloc(1, INET6_ADDRSTRLEN);
    };
    void dump() {
        int32_t delta = lastSent - lastNew;
        std::cout << "Last new int: " << lastNew << " sent: " << lastSent;
        std::cout << " delta: " << delta;
        std::cout << " ints: " << routers.size() << "/" << probes << std::endl;
        for (std::unordered_set<std::string>::iterator iter = routers.begin(); iter != routers.end(); iter++)  
        {
            std::cout << "\t\t" << *iter << std::endl;
        }
    }
    bool add(in6_addr *src, uint32_t elapsed) {
        probes++;
        inet_ntop(AF_INET6, src->s6_addr, source, INET6_ADDRSTRLEN);
        if (routers.find(source) == routers.end()) {
            probes = routers.size() + 1; /* reset probes to parity */
            routers.insert(source);
            lastNew = elapsed;
            return true;
        }
        return false;
    }
    /* look at ratio of discovered routers to probes at TTL */
    bool shouldProbeProb() {
        prob = (float) routers.size() / probes;
        if (prob < prob_thresh)
          return false;
        return true;
    }

    private:
    std::unordered_set<std::string> routers;
    char *source;
};

#endif
