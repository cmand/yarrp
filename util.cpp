/****************************************************************************
   Program:     $Id: util.cpp 32 2015-01-10 23:05:29Z rbeverly $
   Date:        $Date: 2015-01-10 15:05:29 -0800 (Sat, 10 Jan 2015) $
   Description: yarrp misc routines
****************************************************************************/
#include "yarrp.h"
#include <cmath>

/**
 * Returns the number of milliseconds difference between
 * two struct timevals
 *
 * @param end   timeval
 * @param begin timeval
 * @return milliseconds
 */
uint32_t 
tsdiff(struct timeval *end, struct timeval *begin) {
    uint32_t diff = (end->tv_sec - begin->tv_sec) * 1000;
    diff += (end->tv_usec - begin->tv_usec) / 1000;
    return diff;
}

uint32_t 
tsdiffus(struct timeval *end, struct timeval *begin) {
    uint32_t diff = (end->tv_sec - begin->tv_sec) * 1000000;
    diff += (end->tv_usec - begin->tv_usec);
    return diff;
}

double
now(void) {
    struct timeval now;
    gettimeofday(&now, NULL);
    return (double)now.tv_sec + (double)now.tv_usec / 1000000.;
}


/**
 * Sigmoid function
 * http://en.wikipedia.org/wiki/Sigmoid_function
 */
double 
sigmoid(double t) {
    return 1.0 / (1.0 + exp(-t));
}

/**
 * Probability of taking an action, given an input time (t)
 * and range over which to decay.  Example: input milliseconds
 * with a decay from 1 to 0 over an hour timespan:
 *     decayprob(t, 3600*1000)
 */
double 
decayprob(double t, uint32_t range) {
    t = t / (range / 12.0);
    t -= 6;
    return (1.0 - sigmoid(t));
}

double 
decayprob(int32_t t, uint32_t range) {
    return (decayprob((double)t, range));
}

uint8_t 
randuint8() {
    long val = random();
    uint8_t *p = (uint8_t *) & val;
    return *(p + 3);
}

bool 
checkRoot() {
    if ((getuid() != 0) && (geteuid() != 0)) {
        cerr << "** requires root." << endl;
        exit(2);
    }
    return true;
}

double 
zrand() {
    static bool seeded = false;
    if (not seeded) {
        srand48((long)time(NULL));
        seeded = true;
    }
    return drand48();
}

/* generate a random libcperm key */
void permseed(uint8_t *key, uint32_t seed) {
   srand(seed);
   for (int i=0;i<KEYLEN/sizeof(int);i++) {
      int v = rand();
      memcpy(&key[(i*sizeof(int))], &v, sizeof(int));
   }
}

/* generate a random libcperm key */
void permseed(uint8_t *key) {
   permseed(key, time(NULL));
}

/* from: http://www.masaers.com/2013/10/08/Implementing-Poisson-pmf.html */
double poisson_pmf(const double k, const double lambda) {
    return exp(k * log(lambda) - lgamma(k + 1.0) - lambda);
}

/* integral log_2 */
uint32_t intlog(uint32_t in) {
  uint32_t l = 0;
  while (in >>= 1) { ++l; }
  return l;
}

/* Ensure that only one instance of Yarrp is running */
void instanceLock(uint8_t instance) {
  const char *homedir = getenv("HOME");
  if (homedir) {
    char dotdir[1500];
    snprintf(dotdir, 1500, "%s/.yarrp", homedir);
    struct stat st = {0};
    if (stat(dotdir, &st) == -1) {
      mkdir(dotdir, 0755);
    }
    char lockfile[1500];
    snprintf(lockfile, 1500, "%s/lock.%d", dotdir, instance);
    int fd = open(lockfile, O_CREAT | O_RDWR, 0644);
    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    if (fcntl(fd, F_SETLK, &lock) < 0) {
      cerr << "*** " << __func__ << ": Yarrp instance already running." << endl;
      exit(-1);
    }
  } else {
    cerr << "*** " << __func__ << ": getenv" << endl;
    exit(-1);
  }
}
