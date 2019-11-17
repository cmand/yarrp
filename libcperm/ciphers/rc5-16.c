/* 
 * File:    rc5-16.c
 * Author:  zvrba
 * Created: 2008-04-08
 *
 * ===========================================================================
 * COPYRIGHT (c) 2008 Zeljko Vrba <zvrba.external@zvrba.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * ===========================================================================
 */
/**
 * @file
 *
 * RC5 with 16-bit word size (= 32-bit block size).  One of few ciphers (the
 * only?) which supports so small block size.  This is practical because MIPS
 * addressing is also in 32-bit words.  Implementation is based on RFC2040,
 * with some details changed to make it truly independent of the word size.
 */

#include "rc5-16.h"

#if _MSC_VER < 1600
#define	inline	__inline
#endif

#define WSZ		16				/* word size */
#define WW		(WSZ/8)			/* wsz in bytes */
#define BSZ		(2*WW)			/* block size */
#define BB		(BSZ/8)			/* bsz in bytes */
#define b		RC5_KEYLEN		/* key size in bytes */
#define R		RC5_ROUNDS		/* # of rounds */
#define T		(2*(R+1))		/* # of words in expanded key table */
#define LL		((b+WW-1)/WW)	/* # of elts in L (helper array) */
#define P		((RC5_WORD)0xB7E1) /* magic1: (e-2)*(2**W), e=nat log base */
#define Q		((RC5_WORD)0x9E37) /* magic2: (phi-1)*(2**W), phi=golden r.*/
								/* Magic constants must be odd; add 1 if the
								 * formula yields even. */

#if RC5_BLOCKSZ != BSZ
#error "Mismatch between header and source parameters."
#endif

/** Rotate left by n bits. */
static inline RC5_WORD rol(RC5_WORD x, RC5_WORD n)
{
	n &= (WSZ-1);
	return (x << n) | (x >> (WSZ-n));
}

/** Rotate right by n bits. */
static inline RC5_WORD ror(RC5_WORD x, RC5_WORD n)
{
	n &= (WSZ-1);
	return (x >> n) | (x << (WSZ-n));
}

void rc5_setup(struct rc5_key *ks)
{
#define K(i) ((RC5_WORD)ks->key[i])
#define S(i) (ks->S[i])
	int i, j, k, t;
	RC5_WORD A, B, L[LL];

	for(i = 0; i < LL; i++)
		L[i] = 0;
	for(i = 0; i < b; i++) {
		t = K(i) << (8*(i % WW));
		L[i/WW] = L[i/WW] | t;
	}

	S(0) = P;
	for(i = 1; i < T; i++)
		S(i) = S(i-1) + Q;

	i = j = 0;
	A = B = 0;
	if(LL > T)
		k = 3*LL;
	else
		k = 3*T;
	for(; k > 0; k--) {
		A = rol(S(i)+A+B, 3);
		S(i) = A;
		B = rol(L[j]+A+B, A+B);
		L[j] = B;
		i = (i+1) % T;
		j = (j+1) % LL;
	}
#undef K			
#undef S
}

void rc5_ecb_encrypt(const struct rc5_key *ks, void *srcv, void *dstv)
{
#define S(i) (ks->S[i])
	unsigned char *src = (unsigned char *)srcv;
	unsigned char *dst = (unsigned char *)dstv;
	
	RC5_WORD A = (src[0] | (src[1] << 8)) + S(0);
	RC5_WORD B = (src[2] | (src[3] << 8)) + S(1);
	int i;

	for(i = 1; i <= R; i++) {
		A = rol(A^B, B) + S(2*i);
		B = rol(B^A, A) + S(2*i+1);
	}

	dst[0] = A & 0xFF;
	dst[1] = A >> 8;
	dst[2] = B & 0xFF;
	dst[3] = B >> 8;
#undef S
}

void rc5_ecb_decrypt(const struct rc5_key *ks, void *srcv, void *dstv)
{
#define S(i) (ks->S[i])
	unsigned char *src = (unsigned char *)srcv;
	unsigned char *dst = (unsigned char *)dstv;

	RC5_WORD B = (src[3] << 8) | src[2];
	RC5_WORD A = (src[1] << 8) | src[0];
	int i;

	for(i = R; i > 0; i--) {
		B = ror(B-S(2*i+1), A) ^ A;
		A = ror(A-S(2*i), B) ^ B;
	}
	B -= S(1);
	A -= S(0);

	dst[3] = B >> 8;
	dst[2] = B & 0xFF;
	dst[1] = A >> 8;
	dst[0] = A & 0xFF;
#undef S
}

#ifdef RC5_TEST

#include <stdio.h>

/* This test is replicated from rc5ref.c. */

int main(void)
{
	RC5_WORD pt1[2], pt2[2], ct[2] = { 0, 0 };
	struct rc5_key key;
	int i, j;

	for(i = 1; i < 6; i++) {
		pt1[0] = ct[0];
		pt1[1] = ct[1];
		
		for(j = 0; j < b; j++)
			key.key[j] = ct[0] % (255-j);

		rc5_setup(&key);
		rc5_ecb_encrypt(&key, pt1, ct);
		rc5_ecb_decrypt(&key, ct, pt2);

		printf("%d. key = ", i);
		for(j = 0; j < b; j++)
			printf("%.2X ", key.key[j]);
		printf("\n");

		printf("PT %.4hX %.4hX -> CT %.4hX %.4hX -> PT %.4hX %.4hX\n",
			   pt1[0], pt1[1], ct[0], ct[1], pt2[0], pt2[1]);
		if((pt1[0] != pt2[0]) || (pt1[1] != pt2[1]))
			printf("DECRYPTION ERROR!\n");
		printf("\n");
	}
	
	return 0;
}

#endif	/* RC5_TEST */
