/****************************************************************************
   Program:     $Id: status.cpp 32 2015-01-10 23:05:29Z rbeverly $
   Date:        $Date: 2015-01-07 15:59:34 -0800 (Wed, 07 Jan 2015) $
   Description: yarrp status.  A status object exists per-BGP prefix as the
                node data in the patricia trie.  Keep per-prefix status
                information as we proceed through the probing.
****************************************************************************/
#include "yarrp.h"

void
Status::print() {
    int32_t delta = lastReply - lastSent;
    std::cout << ">> Prefix status:" << std::endl;
    std::cout << "\tProbes: " << probes << " Returns: " << returns << std::endl;
    std::cout << "\tLast Probed: " << lastSent << " Last reply: " << lastReply;
    std::cout << " delta: " << delta << std::endl;
    std::cout << "\tTTL high: " << int (highTTL) << " TTL low: " << int (lowTTL) << std::endl;
    printMissingTTL();
}

void
Status::printMissingTTL() {
    std::cout << "\tMissing TTL: ";
    for (std::unordered_set < uint8_t >::iterator iter = missingTTL.begin();
         iter != missingTTL.end();
         iter++) {
        std::cout << int (*iter) << " ";
    }
    std::cout << std::endl;
}

void
Status::reset() {
    probes = 0;
    returns = 0;
    lastReply = 0;
    highTTL = 0;
    lowTTL = UINT8_MAX;
    missingTTL.clear();
}

/*
 * After a prefix is probed, update its status to indicate such
 */
void
Status::probed(uint8_t ttl, uint32_t elapsed) {
    lastSent = elapsed;
    missingTTL.insert(int (ttl));
    probes++;
}

/*
 * After a result comes back in response to a particular prefix being probed,
 * update the prefix's status
 */
void
Status::result(uint8_t ttl, uint32_t elapsed) {
    returns++;
    lastReply = elapsed;
    if (ttl > highTTL)
        highTTL = ttl;
    if (ttl < lowTTL)
        lowTTL = ttl;
    missingTTL.erase(int (ttl));
}

/*
 * Decision function as to whether the prefix should be probed.  Implements a
 * basic stochastic grandient descent
 */
bool
Status::shouldProbe() {
    uint8_t bob = highTTL + 1;
    if (missingTTL.find(bob) == missingTTL.end()) {
//std::cout << __func__ << " got response for last TTL" << std: :endl;
        return true;
    }
    /* If no reply after sending, delta is positive */
    int32_t delta = (lastSent - lastReply);
    double P = decayprob(delta, 60 * 1000);
    double r = zrand();
    std::cout << ">> shouldProbe Delta: " << delta << " P: " << P << " r: " << r << std::endl;
    if (r > P) {
        highTTL++;
        lastReply = lastSent;
    }
    return true;
}
