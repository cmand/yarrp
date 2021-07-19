#ifndef _PATRICIA_H
#define _PATRICIA_H

#define HAVE_IPV6 1

/* typedef unsigned int u_int; */
typedef void (*void_fn_t)();
/* { from defs.h */
#define prefix_touchar(prefix) ((u_char *)&(prefix)->add.sin)
#define MAXLINE 1024
#define BIT_TEST(f, b)  ((f) & (b))
/* } */

#define addroute make_and_lookup

#include <sys/types.h> /* for u_* definitions (on FreeBSD 5) */

#include <errno.h> /* for EAFNOSUPPORT */
#ifndef EAFNOSUPPORT
#  defined EAFNOSUPPORT WSAEAFNOSUPPORT
#  include <winsock.h>
#else
#  include <netinet/in.h> /* for struct in_addr */
#endif

#include <sys/socket.h> /* for AF_INET */

#include <iostream>
#include <sstream>
#include <string>
#include <zlib.h>

typedef struct _prefix4_t {
    u_short family;		/* AF_INET | AF_INET6 */
    u_short bitlen;		/* same as mask? */
    int ref_count;		/* reference count */
    struct in_addr sin;
} prefix4_t;

typedef struct _prefix_t {
    u_short family;		/* AF_INET | AF_INET6 */
    u_short bitlen;		/* same as mask? */
    int ref_count;		/* reference count */
    union {
		struct in_addr sin;
#ifdef HAVE_IPV6
		struct in6_addr sin6;
#endif /* IPV6 */
    } add;
} prefix_t;


typedef struct _patricia_node_t {
   u_int bit;			/* flag if this node used */
   prefix_t *prefix;		/* who we are in patricia tree */
   struct _patricia_node_t *l, *r;	/* left and right children */
   struct _patricia_node_t *parent;/* may be used */
   void *data;			/* pointer to data */
   void *user1;			/* pointer to usr data (ex. route flap info) */
//   unsigned int children;
} patricia_node_t;

typedef struct _patricia_tree_t {
   patricia_node_t 	*head;
   u_int		maxbits;	/* for IP, 32 bit addresses */
   int num_active_node;		/* for debug purpose */
} patricia_tree_t;


patricia_node_t *patricia_search_exact (patricia_tree_t *patricia, prefix_t *prefix);
patricia_node_t *patricia_search_best (patricia_tree_t *patricia, prefix_t *prefix);
patricia_node_t * patricia_search_best2 (patricia_tree_t *patricia, prefix_t *prefix, 
				   int inclusive);
patricia_node_t *patricia_lookup (patricia_tree_t *patricia, prefix_t *prefix);
void patricia_remove (patricia_tree_t *patricia, patricia_node_t *node);
patricia_tree_t *New_Patricia (int maxbits);
void Clear_Patricia (patricia_tree_t *patricia);
void Destroy_Patricia (patricia_tree_t *patricia);
void patricia_process (patricia_tree_t *patricia, void_fn_t func);
const char *prefix_toa (prefix_t * prefix);
patricia_node_t *try_search_best (patricia_tree_t *tree, char *string);
patricia_node_t *try_search_exact (patricia_tree_t *tree, char *string);
size_t patricia_walk_inorder(patricia_node_t *node);
prefix_t *ascii2prefix (int family, const char *string);
prefix_t *int2prefix (uint32_t addr);
void Deref_Prefix(prefix_t *);

#define PATRICIA_MAXBITS 128
#define PATRICIA_NBIT(x)        (0x80 >> ((x) & 0x7f))
#define PATRICIA_NBYTE(x)       ((x) >> 3)

#define PATRICIA_DATA_GET(node, type) (type *)((node)->data)
#define PATRICIA_DATA_SET(node, value) ((node)->data = (void *)(value))

#define PATRICIA_WALK(Xhead, Xnode) \
    do { \
        patricia_node_t *Xstack[PATRICIA_MAXBITS+1]; \
        patricia_node_t **Xsp = Xstack; \
        patricia_node_t *Xrn = (Xhead); \
        while ((Xnode = Xrn)) { \
            if (Xnode->prefix)

#define PATRICIA_WALK_ALL(Xhead, Xnode) \
do { \
        patricia_node_t *Xstack[PATRICIA_MAXBITS+1]; \
        patricia_node_t **Xsp = Xstack; \
        patricia_node_t *Xrn = (Xhead); \
        while ((Xnode = Xrn)) { \
	    if (1)

#define PATRICIA_WALK_BREAK { \
	    if (Xsp != Xstack) { \
		Xrn = *(--Xsp); \
	     } else { \
		Xrn = (patricia_node_t *) 0; \
	    } \
	    continue; }

#define PATRICIA_WALK_END \
            if (Xrn->l) { \
                if (Xrn->r) { \
                    *Xsp++ = Xrn->r; \
                } \
                Xrn = Xrn->l; \
            } else if (Xrn->r) { \
                Xrn = Xrn->r; \
            } else if (Xsp != Xstack) { \
                Xrn = *(--Xsp); \
            } else { \
                Xrn = (patricia_node_t *) 0; \
            } \
        } \
    } while (0)

class Patricia {
    public:
    Patricia(uint8_t size) {
        tree = New_Patricia(size);
    };
    template <typename Type> patricia_node_t *add_ref(const char *string, Type *val) {
        prefix_t *prefix = ascii2prefix(AF_INET, string);
        patricia_node_t *node = patricia_lookup(tree, prefix);
        if (node) {
            if (node->user1 == NULL) {
			    node->user1 = val; 
            }
        }
        Deref_Prefix(prefix);
        return (node);
	}
    //template <typename Type> patricia_node_t *add(const char *string, Type *val);
    template <typename Type> patricia_node_t *add(int family, const char *string, Type *val) {
        size_t size = sizeof(*val);
        prefix_t *prefix = ascii2prefix(family, string);
        patricia_node_t *node = patricia_lookup(tree, prefix);
        if (node) {
            /* only set data if node didn't already exist */
            if (node->user1 == NULL) {
                node->user1 = calloc(1, size);
                memcpy(node->user1, val, size);
            }
        }
        Deref_Prefix(prefix);
        return (node);
    }
    patricia_node_t *add(const char *string, int val) {
        return (add(AF_INET, string, &val));
    }
    patricia_node_t *add(int family, const char *string, int val) {
        return (add(family, string, &val));
    }
    void *get(uint32_t addr, bool exact);
    void *get(uint32_t addr) {
		return (get(addr, false));
	}
    void *get(struct in6_addr addr);
    void *get(int family, const char *string, bool exact);
    void *get(const char *string) {
        return (get(AF_INET, string, false));
    }
    void *get(int family, const char *string) {
        return (get(family, string, false));
    }
    void populate(int family, const char *filename);
    void populate(int family, const char *filename, bool block);
    void populateBlock(int family, const char *filename);
    void populate(const char *filename) {
        populate(AF_INET, filename);
    };
    void populate6(const char *filename) {
        populate(AF_INET6, filename);
    };
    void populateStatus(const char *filename);
    int matchingPrefix(uint32_t addr);
    int matchingPrefix(const char *string);

    private:
    int parseBGPLine(char *, std::string *, uint32_t *, int *);
    int parsePrefix(char *, std::string *);
    void *get(prefix_t *prefix, bool exact);
    int matchingPrefix(prefix_t *prefix);
    patricia_tree_t *tree;
};

#endif /* _PATRICIA_H */


