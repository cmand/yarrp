/* 
 * File:    rc5-16.h
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
 * Interfaces for RC5-16 encryption.
 */

#ifndef RC5_16_H__
#define RC5_16_H__

#define RC5_BLOCKSZ	4			/* (bytes) */
#define RC5_KEYLEN	16			/* (bytes) */
#define RC5_ROUNDS	12			/* # of rounds */

typedef unsigned short RC5_WORD;

struct rc5_key {
	unsigned char key[RC5_KEYLEN];
	RC5_WORD S[2*(RC5_ROUNDS+1)];
};

/**
 * Expand the key.  On entry, the the ks->key field must be initialized with
 * the desired key.
 */
void rc5_setup(struct rc5_key *ks);

/** Encrypt a single block.  It is allowed that src == dst. */
void rc5_ecb_encrypt(const struct rc5_key *ks, void *src, void *dst);

/** Decrypt a single block.  It is allowed that src == dst. */
void rc5_ecb_decrypt(const struct rc5_key *ks, void *src, void *dst);

#endif	/* RC5_16_H__ */
