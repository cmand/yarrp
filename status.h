#ifndef _STATUS_H_
#define _STATUS_H_

#ifndef UINT8_MAX
 #define UINT8_MAX (255)
#endif

#include <unordered_set>

class Status {
    public:
    Status() : probes(0), returns(0), lastSent(0), lastReply(0), 
               highTTL(1), lowTTL(UINT8_MAX)  
    {
        missingTTL.clear();
    };
    void print();
    void reset();
    void probed(uint8_t ttl, uint32_t elapsed);
    void result(uint8_t ttl, uint32_t elapsed);
    uint8_t getTTL() { return highTTL; }
    bool shouldProbe();

    private:
    void printMissingTTL();
    uint16_t probes;
    uint16_t returns;
    uint32_t lastSent;
    uint32_t lastReply;
    uint8_t highTTL;
    uint8_t lowTTL;
    std::unordered_set<uint8_t> missingTTL; 
};

#endif
