/*
 * From Dave Plonka's Net-Patricia-1.22
 *
 * Includes oftware developed by the University of Michigan,
 * Merit Network, Inc., and their contributors.
 */
#include <assert.h> /* assert */
#include <ctype.h> /* isdigit */
#include <errno.h> /* errno */
#include <math.h> /* sin */
#include <stddef.h> /* NULL */
#include <stdio.h> /* sprintf, fprintf, stderr */
#include <stdlib.h> /* free, atol, calloc */
#include <string.h> /* memcpy, strchr, strlen */
#include <sys/types.h> /* BSD: for inet_addr */
#include <sys/socket.h> /* BSD, Linux: for inet_addr */
#include <netinet/in.h> /* BSD, Linux: for inet_addr */
#include <arpa/inet.h> /* BSD, Linux, Solaris: for inet_addr */

#include "patricia.h"
#include "status.h"
#include <algorithm>

#ifdef TESTING
 #include <string>
 #include <iostream>
#endif

/* prefix_tochar
 * convert prefix information to bytes
 */
u_char *
prefix_tochar (prefix_t * prefix)
{
    if (prefix == NULL)
	return (NULL);

    return ((u_char *) & prefix->add.sin);
}

int 
comp_with_mask (void *addr, void *dest, u_int mask)
{
    if ( /* mask/8 == 0 || */ memcmp (addr, dest, mask / 8) == 0) {
	int n = mask / 8;
	int m = ((-1) << (8 - (mask % 8)));

	if (mask % 8 == 0 || (((u_char *)addr)[n] & m) == (((u_char *)dest)[n] & m))
	    return (1);
    }
    return (0);
}

/* this allows imcomplete prefix */
int
my_inet_pton (int af, const char *src, void *dst)
{
    if (af == AF_INET) {
        int i, c, val;
        u_char xp[sizeof(struct in_addr)] = {0, 0, 0, 0};

        for (i = 0; ; i++) {
	    c = *src++;
	    if (!isdigit (c))
		return (-1);
	    val = 0;
	    do {
		val = val * 10 + c - '0';
		if (val > 255)
		    return (0);
		c = *src++;
	    } while (c && isdigit (c));
            xp[i] = val;
	    if (c == '\0')
		break;
            if (c != '.')
                return (0);
	    if (i >= 3)
		return (0);
        }
	memcpy (dst, xp, sizeof(struct in_addr));
        return (1);
#ifdef HAVE_IPV6
    } else if (af == AF_INET6) {
        return (inet_pton (af, src, dst));
#endif /* HAVE_IPV6 */
    } else {
	errno = EAFNOSUPPORT;
	return -1;
    }
}

#define PATRICIA_MAX_THREADS		16

/* 
 * convert prefix information to ascii string with length
 * thread safe and (almost) re-entrant implementation
 */
const char *
prefix_toa2x (prefix_t *prefix, char *buff, int with_len)
{
    if (prefix == NULL)
	return ("(Null)");
    assert (prefix->ref_count >= 0);
    if (buff == NULL) {

        struct buffer {
            char buffs[PATRICIA_MAX_THREADS][48+5];
            u_int i;
        } *buffp;

        { /* for scope only */
	   static struct buffer local_buff;
           buffp = &local_buff;
	}
	if (buffp == NULL) {
	    /* XXX should we report an error? */
	    return (NULL);
	}

	buff = buffp->buffs[buffp->i++%PATRICIA_MAX_THREADS];
    }
    if (prefix->family == AF_INET) {
	u_char *a;
	assert (prefix->bitlen <= sizeof(struct in_addr) * 8);
	a = prefix_touchar (prefix);
	if (with_len) {
	    sprintf (buff, "%d.%d.%d.%d/%d", a[0], a[1], a[2], a[3],
		     prefix->bitlen);
	}
	else {
	    sprintf (buff, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
	}
	return (buff);
    }
#ifdef HAVE_IPV6
    else if (prefix->family == AF_INET6) {
	char *r;
	r = (char *) inet_ntop (AF_INET6, &prefix->add.sin6, buff, 48 /* a guess value */ );
	if (r && with_len) {
	    assert (prefix->bitlen <= sizeof(struct in6_addr) * 8);
	    sprintf (buff + strlen (buff), "/%d", prefix->bitlen);
	}
	return (buff);
    }
#endif /* HAVE_IPV6 */
    else
	return (NULL);
}

/* prefix_toa2
 * convert prefix information to ascii string
 */
const char *
prefix_toa2 (prefix_t *prefix, char *buff)
{
    return (prefix_toa2x (prefix, buff, 0));
}

/* prefix_toa
 */
const char *
prefix_toa (prefix_t * prefix)
{
    return (prefix_toa2 (prefix, (char *) NULL));
}

prefix_t *
New_Prefix2 (int family, void *dest, int bitlen, prefix_t *prefix)
{
    int dynamic_allocated = 0;
    int default_bitlen = sizeof(struct in_addr) * 8;

#ifdef HAVE_IPV6
    if (family == AF_INET6) {
        default_bitlen = sizeof(struct in6_addr) * 8;
	if (prefix == NULL) {
            prefix = (prefix_t *) calloc(1, sizeof (prefix_t));
	    dynamic_allocated++;
	}
	memcpy (&prefix->add.sin6, dest, sizeof(struct in6_addr));
    }
    else
#endif /* HAVE_IPV6 */
    if (family == AF_INET) {
	if (prefix == NULL) {
            prefix = (prefix_t *) calloc(1, sizeof (prefix4_t));
	    dynamic_allocated++;
	}
	memcpy (&prefix->add.sin, dest, sizeof(struct in_addr));
    }
    else {
        return (NULL);
    }

    prefix->bitlen = (bitlen >= 0)? bitlen: default_bitlen;
    prefix->family = family;
    prefix->ref_count = 0;
    if (dynamic_allocated) {
        prefix->ref_count++;
   }
/* fprintf(stderr, "[C %s, %d]\n", prefix_toa (prefix), prefix->ref_count); */
    return (prefix);
}

prefix_t *
New_Prefix (int family, void *dest, int bitlen)
{
    return (New_Prefix2 (family, dest, bitlen, NULL));
}

prefix_t *
int2prefix (uint32_t addr)
{
    struct in_addr sin;
    sin.s_addr = addr;
    return (New_Prefix (AF_INET, &sin, 32));
}

/* ascii2prefix
 */
prefix_t *
ascii2prefix (int family, const char *string)
{
    u_long bitlen, maxbitlen = 0;
    const char *cp;
    struct in_addr sin;
#ifdef HAVE_IPV6
    struct in6_addr sin6;
#endif /* HAVE_IPV6 */
    int result;
    char save[MAXLINE];

    if (string == NULL)
	return (NULL);

    /* easy way to handle both families */
    if (family == 0) {
       family = AF_INET;
#ifdef HAVE_IPV6
       if (strchr (string, ':')) family = AF_INET6;
#endif /* HAVE_IPV6 */
    }

    if (family == AF_INET) {
	maxbitlen = sizeof(struct in_addr) * 8;
    }
#ifdef HAVE_IPV6
    else if (family == AF_INET6) {
	maxbitlen = sizeof(struct in6_addr) * 8;
    }
#endif /* HAVE_IPV6 */

    if ((cp = strchr (string, '/')) != NULL) {
	bitlen = atol (cp + 1);
	/* *cp = '\0'; */
	/* copy the string to save. Avoid destroying the string */
	assert (cp - string < MAXLINE);
	memcpy (save, string, cp - string);
	save[cp - string] = '\0';
	string = save;
	if (bitlen > maxbitlen)
	    bitlen = maxbitlen;
	}
	else {
	    bitlen = maxbitlen;
	}

	if (family == AF_INET) {
	    if ((result = my_inet_pton (AF_INET, string, &sin)) <= 0)
		return (NULL);
	    return (New_Prefix (AF_INET, &sin, bitlen));
	}

#ifdef HAVE_IPV6
	else if (family == AF_INET6) {
	    if ((result = inet_pton (AF_INET6, string, &sin6)) <= 0)
		return (NULL);
	    return (New_Prefix (AF_INET6, &sin6, bitlen));
	}
#endif /* HAVE_IPV6 */
	else
	    return (NULL);
}

prefix_t *
Ref_Prefix (prefix_t * prefix)
{
    if (prefix == NULL)
	return (NULL);
    if (prefix->ref_count == 0) {
	/* make a copy in case of a static prefix */
        return (New_Prefix2 (prefix->family, &prefix->add, prefix->bitlen, NULL));
    }
    prefix->ref_count++;
/* fprintf(stderr, "[A %s, %d]\n", prefix_toa (prefix), prefix->ref_count); */
    return (prefix);
}

void 
Deref_Prefix (prefix_t * prefix)
{
    if (prefix == NULL)
	return;
    /* for secure programming, raise an assert. no static prefix can call this */
    assert (prefix->ref_count > 0);

    prefix->ref_count--;
    assert (prefix->ref_count >= 0);
    if (prefix->ref_count <= 0) {
	free (prefix);
	return;
    }
}


/* #define PATRICIA_DEBUG 1 */

static int num_active_patricia = 0;

/* these routines support continuous mask only */

patricia_tree_t *
New_Patricia (int maxbits)
{
    patricia_tree_t *patricia = (patricia_tree_t*) calloc(1, sizeof *patricia);

    patricia->maxbits = maxbits;
    patricia->head = NULL;
    patricia->num_active_node = 0;
    assert (maxbits <= PATRICIA_MAXBITS); /* XXX */
    num_active_patricia++;
    return (patricia);
}


/*
 * if func is supplied, it will be called as func(node->data)
 * before deleting the node
 */

void
Clear_Patricia (patricia_tree_t *patricia)
{
    assert (patricia);
    if (patricia->head) {

        patricia_node_t *Xstack[PATRICIA_MAXBITS+1];
        patricia_node_t **Xsp = Xstack;
        patricia_node_t *Xrn = patricia->head;

        while (Xrn) {
            patricia_node_t *l = Xrn->l;
            patricia_node_t *r = Xrn->r;

    	    if (Xrn->prefix) {
		Deref_Prefix (Xrn->prefix);
    	    }
    	    else {
		assert (Xrn->data == NULL);
    	    }
    	    free (Xrn);
	    patricia->num_active_node--;

            if (l) {
                if (r) {
                    *Xsp++ = r;
                }
                Xrn = l;
            } else if (r) {
                Xrn = r;
            } else if (Xsp != Xstack) {
                Xrn = *(--Xsp);
            } else {
                Xrn = (patricia_node_t *) NULL;
            }

        }
    }
    assert (patricia->num_active_node == 0);
    /* free (patricia); */
}


void
Destroy_Patricia (patricia_tree_t *patricia)
{
    Clear_Patricia (patricia);
    free (patricia);
    num_active_patricia--;
}

/*
 * if func is supplied, it will be called as func(node->prefix, node->data)
 */

/*
void
patricia_process (patricia_tree_t *patricia, void_fn_t func)
{
    patricia_node_t *node;
    assert (func);

    PATRICIA_WALK (patricia->head, node) {
	func (node->prefix, node->data);
    } PATRICIA_WALK_END;
}
*/

void print_node(patricia_node_t *node) {
    FILE *fp = stdout;
    prefix_t *p = node->prefix;
    if (p)
        fprintf(fp, "Prefix: %s/%d (used? %d)\n", inet_ntoa(p->add.sin), p->bitlen, node->bit);
}


size_t
patricia_walk_inorder(patricia_node_t *node)
{
    size_t n = 0;

    if (node->l) {
         n += patricia_walk_inorder(node->l);
    }

    if (node->prefix) {
	n++;
    }
	
    if (node->r) {
         n += patricia_walk_inorder(node->r);
    }

    return n;
}


patricia_node_t *
patricia_search_exact (patricia_tree_t *patricia, prefix_t *prefix)
{
    patricia_node_t *node;
    u_char *addr;
    u_int bitlen;

    assert (patricia);
    assert (prefix);
    assert (prefix->bitlen <= patricia->maxbits);

    if (patricia->head == NULL)
	return (NULL);

    node = patricia->head;
    addr = prefix_touchar (prefix);
    bitlen = prefix->bitlen;

    while (node->bit < bitlen) {

	if (BIT_TEST (addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
#ifdef PATRICIA_DEBUG
	    if (node->prefix)
    	        fprintf (stderr, "patricia_search_exact: take right %s/%d\n", 
	                 prefix_toa (node->prefix), node->prefix->bitlen);
	    else
    	        fprintf (stderr, "patricia_search_exact: take right at %d\n", 
			 node->bit);
#endif /* PATRICIA_DEBUG */
	    node = node->r;
	}
	else {
#ifdef PATRICIA_DEBUG
	    if (node->prefix)
    	        fprintf (stderr, "patricia_search_exact: take left %s/%d\n", 
	                 prefix_toa (node->prefix), node->prefix->bitlen);
	    else
    	        fprintf (stderr, "patricia_search_exact: take left at %d\n", 
			 node->bit);
#endif /* PATRICIA_DEBUG */
	    node = node->l;
	}

	if (node == NULL)
	    return (NULL);
    }

#ifdef PATRICIA_DEBUG
    if (node->prefix)
        fprintf (stderr, "patricia_search_exact: stop at %s/%d\n", 
	         prefix_toa (node->prefix), node->prefix->bitlen);
    else
        fprintf (stderr, "patricia_search_exact: stop at %d\n", node->bit);
#endif /* PATRICIA_DEBUG */
    if (node->bit > bitlen || node->prefix == NULL)
	return (NULL);
    assert (node->bit == bitlen);
    assert (node->bit == node->prefix->bitlen);
    if (comp_with_mask (prefix_tochar (node->prefix), prefix_tochar (prefix),
			bitlen)) {
#ifdef PATRICIA_DEBUG
        fprintf (stderr, "patricia_search_exact: found %s/%d\n", 
	         prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	return (node);
    }
    return (NULL);
}


/* if inclusive != 0, "best" may be the given prefix itself */
patricia_node_t *
patricia_search_best2 (patricia_tree_t *patricia, prefix_t *prefix, int inclusive)
{
    patricia_node_t *node;
    patricia_node_t *stack[PATRICIA_MAXBITS + 1];
    u_char *addr;
    u_int bitlen;
    int cnt = 0;

    assert (patricia);
    assert (prefix);
    assert (prefix->bitlen <= patricia->maxbits);

    if (patricia->head == NULL)
	return (NULL);

    node = patricia->head;
    addr = prefix_touchar (prefix);
    bitlen = prefix->bitlen;

    while (node->bit < bitlen) {

	if (node->prefix) {
#ifdef PATRICIA_DEBUG
            fprintf (stderr, "patricia_search_best: push %s/%d\n", 
	             prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	    stack[cnt++] = node;
	}

	if (BIT_TEST (addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
#ifdef PATRICIA_DEBUG
	    if (node->prefix)
    	        fprintf (stderr, "patricia_search_best: take right %s/%d\n", 
	                 prefix_toa (node->prefix), node->prefix->bitlen);
	    else
    	        fprintf (stderr, "patricia_search_best: take right at %d\n", 
			 node->bit);
#endif /* PATRICIA_DEBUG */
	    node = node->r;
	}
	else {
#ifdef PATRICIA_DEBUG
	    if (node->prefix)
    	        fprintf (stderr, "patricia_search_best: take left %s/%d\n", 
	                 prefix_toa (node->prefix), node->prefix->bitlen);
	    else
    	        fprintf (stderr, "patricia_search_best: take left at %d\n", 
			 node->bit);
#endif /* PATRICIA_DEBUG */
	    node = node->l;
	}

	if (node == NULL)
	    break;
    }

    if (inclusive && node && node->prefix)
	stack[cnt++] = node;

#ifdef PATRICIA_DEBUG
    if (node == NULL)
        fprintf (stderr, "patricia_search_best: stop at null\n");
    else if (node->prefix)
        fprintf (stderr, "patricia_search_best: stop at %s/%d\n", 
	         prefix_toa (node->prefix), node->prefix->bitlen);
    else
        fprintf (stderr, "patricia_search_best: stop at %d\n", node->bit);
#endif /* PATRICIA_DEBUG */

    if (cnt <= 0)
	return (NULL);

    while (--cnt >= 0) {
	node = stack[cnt];
#ifdef PATRICIA_DEBUG
        fprintf (stderr, "patricia_search_best: pop %s/%d\n", 
	         prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	if (comp_with_mask (prefix_tochar (node->prefix), 
			    prefix_tochar (prefix),
			    node->prefix->bitlen) && node->prefix->bitlen <= bitlen) {
#ifdef PATRICIA_DEBUG
            fprintf (stderr, "patricia_search_best: found %s/%d\n", 
	             prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	    return (node);
	}
    }
    return (NULL);
}


patricia_node_t *
patricia_search_best (patricia_tree_t *patricia, prefix_t *prefix)
{
    return (patricia_search_best2 (patricia, prefix, 1));
}


patricia_node_t *
patricia_lookup (patricia_tree_t *patricia, prefix_t *prefix)
{
    patricia_node_t *node, *new_node, *parent, *glue;
    u_char *addr, *test_addr;
    u_int bitlen, check_bit, differ_bit;
    u_int i;
    int j, r;

    assert (patricia);
    assert (prefix);
    assert (prefix->bitlen <= patricia->maxbits);

    if (patricia->head == NULL) {
	node = (patricia_node_t *) calloc(1, sizeof *node);
	node->bit = prefix->bitlen;
	node->prefix = Ref_Prefix (prefix);
	node->parent = NULL;
	node->l = node->r = NULL;
	node->data = NULL;
	patricia->head = node;
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_lookup: new_node #0 %s/%d (head)\n", 
		 prefix_toa (prefix), prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	patricia->num_active_node++;
	return (node);
    }

    addr = prefix_touchar (prefix);
    bitlen = prefix->bitlen;
    node = patricia->head;

    while (node->bit < bitlen || node->prefix == NULL) {

	if (node->bit < patricia->maxbits &&
	    BIT_TEST (addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
	    if (node->r == NULL)
		break;
#ifdef PATRICIA_DEBUG
	    if (node->prefix)
    	        fprintf (stderr, "patricia_lookup: take right %s/%d\n", 
	                 prefix_toa (node->prefix), node->prefix->bitlen);
	    else
    	        fprintf (stderr, "patricia_lookup: take right at %d\n", node->bit);
#endif /* PATRICIA_DEBUG */
	    node = node->r;
	}
	else {
	    if (node->l == NULL)
		break;
#ifdef PATRICIA_DEBUG
	    if (node->prefix)
    	        fprintf (stderr, "patricia_lookup: take left %s/%d\n", 
	             prefix_toa (node->prefix), node->prefix->bitlen);
	    else
    	        fprintf (stderr, "patricia_lookup: take left at %d\n", node->bit);
#endif /* PATRICIA_DEBUG */
	    node = node->l;
	}

	assert (node);
    }

    assert (node->prefix);
#ifdef PATRICIA_DEBUG
    fprintf (stderr, "patricia_lookup: stop at %s/%d\n", 
	     prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */

    test_addr = prefix_touchar (node->prefix);
    /* find the first bit different */
    check_bit = (node->bit < bitlen)? node->bit: bitlen;
    differ_bit = 0;
    for (i = 0; i*8 < check_bit; i++) {
	if ((r = (addr[i] ^ test_addr[i])) == 0) {
	    differ_bit = (i + 1) * 8;
	    continue;
	}
	/* I know the better way, but for now */
	for (j = 0; j < 8; j++) {
	    if (BIT_TEST (r, (0x80 >> j)))
		break;
	}
	/* must be found */
	assert (j < 8);
	differ_bit = i * 8 + j;
	break;
    }
    if (differ_bit > check_bit)
	differ_bit = check_bit;
#ifdef PATRICIA_DEBUG
    fprintf (stderr, "patricia_lookup: differ_bit %d\n", differ_bit);
#endif /* PATRICIA_DEBUG */

    parent = node->parent;
    while (parent && parent->bit >= differ_bit) {
	node = parent;
	parent = node->parent;
#ifdef PATRICIA_DEBUG
	if (node->prefix)
            fprintf (stderr, "patricia_lookup: up to %s/%d\n", 
	             prefix_toa (node->prefix), node->prefix->bitlen);
	else
            fprintf (stderr, "patricia_lookup: up to %d\n", node->bit);
#endif /* PATRICIA_DEBUG */
    }

    if (differ_bit == bitlen && node->bit == bitlen) {
	if (node->prefix) {
#ifdef PATRICIA_DEBUG 
    	    fprintf (stderr, "patricia_lookup: found %s/%d\n", 
		     prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	    return (node);
	}
	node->prefix = Ref_Prefix (prefix);
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_lookup: new node #1 %s/%d (glue mod)\n",
		 prefix_toa (prefix), prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	assert (node->data == NULL);
	return (node);
    }

    new_node = (patricia_node_t *) calloc(1, sizeof *new_node);
    new_node->bit = prefix->bitlen;
    new_node->prefix = Ref_Prefix (prefix);
    new_node->parent = NULL;
    new_node->l = new_node->r = NULL;
    new_node->data = NULL;
    patricia->num_active_node++;

    if (node->bit == differ_bit) {
	new_node->parent = node;
	if (node->bit < patricia->maxbits &&
	    BIT_TEST (addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
	    assert (node->r == NULL);
	    node->r = new_node;
	}
	else {
	    assert (node->l == NULL);
	    node->l = new_node;
	}
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_lookup: new_node #2 %s/%d (child)\n", 
		 prefix_toa (prefix), prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	return (new_node);
    }

    if (bitlen == differ_bit) {
	if (bitlen < patricia->maxbits &&
	    BIT_TEST (test_addr[bitlen >> 3], 0x80 >> (bitlen & 0x07))) {
	    new_node->r = node;
	}
	else {
	    new_node->l = node;
	}
	new_node->parent = node->parent;
	if (node->parent == NULL) {
	    assert (patricia->head == node);
	    patricia->head = new_node;
	}
	else if (node->parent->r == node) {
	    node->parent->r = new_node;
	}
	else {
	    node->parent->l = new_node;
	}
	node->parent = new_node;
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_lookup: new_node #3 %s/%d (parent)\n", 
		 prefix_toa (prefix), prefix->bitlen);
#endif /* PATRICIA_DEBUG */
    }
    else {
        glue = (patricia_node_t *) calloc(1, sizeof *glue);
        glue->bit = differ_bit;
        glue->prefix = NULL;
        glue->parent = node->parent;
        glue->data = NULL;
        patricia->num_active_node++;
	if (differ_bit < patricia->maxbits &&
	    BIT_TEST (addr[differ_bit >> 3], 0x80 >> (differ_bit & 0x07))) {
	    glue->r = new_node;
	    glue->l = node;
	}
	else {
	    glue->r = node;
	    glue->l = new_node;
	}
	new_node->parent = glue;

	if (node->parent == NULL) {
	    assert (patricia->head == node);
	    patricia->head = glue;
	}
	else if (node->parent->r == node) {
	    node->parent->r = glue;
	}
	else {
	    node->parent->l = glue;
	}
	node->parent = glue;
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_lookup: new_node #4 %s/%d (glue+node)\n", 
		 prefix_toa (prefix), prefix->bitlen);
#endif /* PATRICIA_DEBUG */
    }
    return (new_node);
}


void
patricia_remove (patricia_tree_t *patricia, patricia_node_t *node)
{
    patricia_node_t *parent, *child;

    assert (patricia);
    assert (node);

	printf("** %s\n", __func__);
    if (node->r && node->l) {
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_remove: #0 %s/%d (r & l)\n", 
		 prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	
	/* this might be a placeholder node -- have to check and make sure
	 * there is a prefix aossciated with it ! */
	if (node->prefix != NULL) 
	  Deref_Prefix (node->prefix);
	node->prefix = NULL;
	/* Also I needed to clear data pointer -- masaki */
	node->data = NULL;
	return;
    }

    if (node->r == NULL && node->l == NULL) {
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_remove: #1 %s/%d (!r & !l)\n", 
		 prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	parent = node->parent;
	Deref_Prefix (node->prefix);
	free (node);
        patricia->num_active_node--;

	if (parent == NULL) {
	    assert (patricia->head == node);
	    patricia->head = NULL;
	    return;
	}

	if (parent->r == node) {
	    parent->r = NULL;
	    child = parent->l;
	}
	else {
	    assert (parent->l == node);
	    parent->l = NULL;
	    child = parent->r;
	}

	if (parent->prefix)
	    return;

	/* we need to remove parent too */

	if (parent->parent == NULL) {
	    assert (patricia->head == parent);
	    patricia->head = child;
	}
	else if (parent->parent->r == parent) {
	    parent->parent->r = child;
	}
	else {
	    assert (parent->parent->l == parent);
	    parent->parent->l = child;
	}
	child->parent = parent->parent;
	free (parent);
        patricia->num_active_node--;
	return;
    }

#ifdef PATRICIA_DEBUG
    fprintf (stderr, "patricia_remove: #2 %s/%d (r ^ l)\n", 
	     prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
    if (node->r) {
	child = node->r;
    }
    else {
	assert (node->l);
	child = node->l;
    }
    parent = node->parent;
    child->parent = parent;

    Deref_Prefix (node->prefix);
    free (node);
    patricia->num_active_node--;

    if (parent == NULL) {
	assert (patricia->head == node);
	patricia->head = child;
	return;
    }

    if (parent->r == node) {
	parent->r = child;
    }
    else {
        assert (parent->l == node);
	parent->l = child;
    }
}

patricia_node_t *
try_search_exact (patricia_tree_t *tree, char *string)
{
    prefix_t *prefix;
    patricia_node_t *node;

    prefix = ascii2prefix (AF_INET, string);
    printf ("try_search_exact: %s/%d\n", prefix_toa (prefix), prefix->bitlen);
    if ((node = patricia_search_exact (tree, prefix)) == NULL) {
        printf ("try_search_exact: not found\n");
    }
    else {
        printf ("try_search_exact: %s/%d found\n", 
	        prefix_toa (node->prefix), node->prefix->bitlen);
    }
    Deref_Prefix (prefix);
    return (node);
}

patricia_node_t *
try_search_best (patricia_tree_t *tree, char *string)
{
    prefix_t *prefix;
    patricia_node_t *node;

    prefix = ascii2prefix (AF_INET, string);
    printf ("try_search_best: %s/%d\n", prefix_toa (prefix), prefix->bitlen);
    if ((node = patricia_search_best (tree, prefix)) == NULL)
        printf ("try_search_best: not found\n");
    else {
        printf ("try_search_best: %s/%d found\n", 
	        prefix_toa (node->prefix), node->prefix->bitlen);
        if (node->user1 != NULL) {
            unsigned short *s = (unsigned short *) node->user1;
            printf("NextHop AS: %d\n", *s);
        }
    }
    Deref_Prefix (prefix);
    return (node);
}

void *Patricia::get(prefix_t *prefix, bool exact) {
    void *retval = NULL;
    patricia_node_t *node;
    if (exact)
        node = patricia_search_exact(tree, prefix);
    else
        node = patricia_search_best(tree, prefix);
    if ( (node) and (node->user1) )
        retval = node->user1;

    Deref_Prefix (prefix);
    return retval;
}

void *Patricia::get(int family, const char *string, bool exact) {
    prefix_t *prefix = ascii2prefix(family, string);
    return get(prefix, exact);
}

void *Patricia::get(uint32_t addr, bool exact) {
    prefix_t *prefix = int2prefix(addr);
    return get(prefix, exact);
}

void *Patricia::get(struct in6_addr addr) {
    prefix_t *prefix = New_Prefix(AF_INET6, &addr, 128);
    return get(prefix, false);
}

int Patricia::matchingPrefix(prefix_t *prefix) {
    patricia_node_t *node = patricia_search_best(tree, prefix);
    static char prefix_str[1500];
    prefix_toa2x(prefix, prefix_str, true);
    //std::cout << __func__ << ">> " << prefix_str << " ";
    int *asn;
    if (node) {
        asn = (int *) node->user1;
        //std::cout << "value: " << *asn << std::endl;
        return *asn;
    } else {
        //std::cout << "matches no prefix." << std::endl;
        return -1;
    }
}

int Patricia::matchingPrefix(uint32_t addr) {
    prefix_t *prefix = int2prefix(addr);
    return matchingPrefix(prefix);
}

int Patricia::matchingPrefix(const char *string, int family) {
    prefix_t *prefix = ascii2prefix(family, string);
    return matchingPrefix(prefix);
}

int Patricia::parsePrefix(int family, char *_line, std::string *p) {
    std::string line(_line);
    // remove whitespace
    line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
    line.erase(std::remove(line.begin(), line.end(), ' '), line.end());
    std::string::size_type slash = line.find_first_of("/");
    int mask = 0;
    std::istringstream(line.substr(slash+1, line.length())) >> mask;
    std::string net = line.substr(0,slash);
    struct in_addr dummy;
    if (family == AF_INET6) {
      struct in6_addr dummy;
      if ((inet_pton(AF_INET6, net.c_str(), &dummy) != 1) or (mask < 0) or (mask > 128)) {
        std::cerr << "Badly formed IPv6 block prefix: [" << line << "]" << std::endl;
        exit(-1);
      }
    } else {
      struct in_addr dummy;
      if ((inet_pton(AF_INET, net.c_str(), &dummy) != 1) or (mask < 0) or (mask > 32)) {
        std::cerr << "Badly formed IPv4 block prefix: [" << line << "]" << std::endl;
        exit(-1);
      }
    }
    *p = line;
    return 1;
}

int Patricia::parseBGPLine(char *_line, std::string *net, uint32_t *asn, int *family) {
    std::string line(_line);
    std::string::size_type first_space, last_space, first_non_white;
    first_non_white = line.find_first_not_of(' ');
    first_space = line.find(' ', first_non_white);
    last_space = line.rfind(' ');
    if (line.find('>') != std::string::npos) {
        *net = line.substr(first_non_white+1,first_space-1);
    } else {
        *net = line.substr(first_non_white,first_space-1);
    }

    /* infer the address family (v4/v6) of the entry */
    std::string pre;
    std::string::size_type slash;
    slash = net->find('/');
    pre = net->substr(0,slash);
    struct in_addr dummy;
    if (inet_aton(pre.c_str(), &dummy) == 1)
        *family = AF_INET;
    else
        *family = AF_INET6;

    /* grab origin ASN */
    std::string asn_str = line.substr(last_space);
    asn_str = asn_str.substr(0,asn_str.length()-1);
    std::stringstream ss;
    ss.str(asn_str);
    ss >> *asn;
    return 1;
}

void Patricia::populate(int family, const char *filename) {
    populate(family, filename, false);
}

void Patricia::populateBlock(int family, const char *filename) {
    populate(family, filename, true);
}

/*  we have two types of entries in the table:
 *  0 => prefix is blacklisted
 *  ASN => prefix's AS number
 */
void Patricia::populate(int family, const char *filename, bool block) {
    gzFile f = gzopen(filename, "r");
    assert(f);
    char line[MAXLINE];
    std::string network;
    uint32_t asn;
    int bgpfamily;
    while (!gzeof(f)) {
        if (gzgets(f, line, MAXLINE) == NULL) break;
        if (block) {
            if (parsePrefix(family, line, &network)) {
                //std::cout << "Block Prefix: " << network << std::endl;
                add(family, network.c_str(), 0); 
            }
        } else {
            if (parseBGPLine(line, &network, &asn, &bgpfamily)) {
                // IP address family in bgptable different than current mode (v4/v6)
                if (bgpfamily != family)
                  continue;
                // lookup first, ensure prefix isn't contained in a blacklistd prefix
                if ( matchingPrefix(network.c_str(), family) != 0 )
                  add(family, network.c_str(), asn); 
            }
        }
    }
    gzclose(f);
}

void Patricia::populateStatus(const char *filename) {
    gzFile f = gzopen(filename, "r");
    assert(f);
    char line[MAXLINE];
    std::string network;
    uint32_t asn;
    int bgpfamily;
    /* Only need to create one status object; Patricia::add memcpy's */
    //Status *status = new Status;
    while (!gzeof(f)) {
        if (gzgets(f, line, MAXLINE) == NULL) break;
        if (parseBGPLine(line, &network, &asn, &bgpfamily)) {
            Status *status = new Status;
            add_ref(network.c_str(), status); 
            //std::cout << "Prefix: " << network << "ASN: " << asn << std::endl;
        }
    }
    gzclose(f);
}

#ifdef TESTING
int main() {
#ifdef IPV6
    Patricia *tree = new Patricia(128);
    std::cout << "Populating" << std::endl;
    // populate from http://bgp.potaroo.net/v6/as6447/bgptable.txt
    tree->populate6("bgptable6.txt.gz");
    int *asn;
    asn = (int *) tree->get(AF_INET6, "2001:470:8b2d:1a:5054:ff:fe61:1a14");
    std::cout << "ASN: " << *asn << std::endl;
    asn = (int *) tree->get(AF_INET6, "2607:f380:804:410:1::100");
    std::cout << "ASN: " << *asn << std::endl;
    exit(-1);

    std::cout << "Adding" << std::endl;
    tree->add(AF_INET6, "2001::0/16", 1234);
    std::cout << "Adding" << std::endl;
    tree->add(AF_INET6, "2001:0218::0/32", 9999);
    std::cout << "Adding" << std::endl;
    tree->add(AF_INET6, "2001:0218:0204::0/48", 7);
    std::cout << "Lookup" << std::endl;
    asn = (int *) tree->get(AF_INET6, "2001:470:8b2d:1a:5054:ff:fe61:1a14");
    std::cout << "ASN: " << *asn << std::endl;
    asn = (int *) tree->get(AF_INET6, "2001:218:8b2d:1a:5054:ff:fe61:1a14");
    std::cout << "ASN: " << *asn << std::endl;
    asn = (int *) tree->get(AF_INET6, "2001:218:0204:1a:5054:ff:fe61:1a14");
    std::cout << "ASN: " << *asn << std::endl;
#else
    Patricia *tree = new Patricia(32);

    // populate from http://bgp.potaroo.net/as6447/bgptable.txt
    // $ grep ">" bgptable.txt | gzip -c - > bgptable.txt.gz
    int *asn;
    tree->populate("bgptable.txt.gz");
    asn = (int *) tree->get("1.92.1.2");
    std::cout << "ASN: " << *asn << std::endl;
    asn = (int *) tree->get("1.94.1.2");
    std::cout << "ASN: " << *asn << std::endl;
    exit(-1);

    // add/lookup integers
    tree->add("18.0.0.0/8", 1234);
    tree->add("18.11.0.0/16", 4321);
    tree->add("18.11.12.0/24", 9999);
    assert(tree->get("18.12.9.1") != NULL);
    asn = (int *) tree->get("18.12.9.1");
    std::cout << "ASN: " << *asn << std::endl;
    asn = (int *) tree->get("18.11.9.1");
    std::cout << "ASN: " << *asn << std::endl;
    asn = (int *) tree->get("18.11.12.1");
    std::cout << "ASN: " << *asn << std::endl;
    asn = (int *) tree->get(htonl(302736483));
    std::cout << "ASN: " << *asn << std::endl;

    // add/lookup object
    std::string data = "this is some data";
    //tree->add_ref("99.2.0.0/16", &data);
    tree->add_ref("1.2.0.0/16", &data);
    assert(tree->get("1.2.3.4") != NULL);
    //std::string *result = (std::string *) tree->get("99.2.3.4");
    std::string *result = (std::string *) tree->get("1.2.3.4");
    std::cout << "Got: " << *result << std::endl;
#endif
}
#endif
