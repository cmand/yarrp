/*
Copyright (c) 2016, Moritz Bitsch

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
#ifndef SPECK_H
#define SPECK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../cperm.h"
#include "../cperm-internal.h"

#define MASK24 0xFFFFFF
#define MASK48 0xFFFFFFFFFFFF

/*
 * define speck type to use (one of SPECK_32_64, SPECK_64_128, SPECK_128_256)
 */
#define SPECK_32_64

#ifdef SPECK_32_64
#define SPECK_TYPE uint16_t
#define SPECK_ROUNDS 22
#define SPECK_KEY_LEN 4
#endif

#ifdef SPECK_48_72
#define SPECK_TYPE uint32_t
#define SPECK_ROUNDS 22
#define SPECK_KEY_LEN 3
#define WORDSIZE 24
#endif

#ifdef SPECK_48_96
#define SPECK_TYPE uint32_t
#define SPECK_ROUNDS 23
#define SPECK_KEY_LEN 4
#define WORDSIZE 24
#endif

#ifdef SPECK_64_128
#define SPECK_TYPE uint32_t
#define SPECK_ROUNDS 27
#define SPECK_KEY_LEN 4
#endif

#ifdef SPECK_96_96
#define SPECK_TYPE uint64_t
#define SPECK_ROUNDS 28
#define SPECK_KEY_LEN 2
#define WORDSIZE 48
#endif

#ifdef SPECK_96_144
#define SPECK_TYPE uint64_t
#define SPECK_ROUNDS 29
#define SPECK_KEY_LEN 3
#define WORDSIZE 48
#endif

#ifdef SPECK_128_256
#define SPECK_TYPE uint64_t
#define SPECK_ROUNDS 34
#define SPECK_KEY_LEN 4
#endif

void speck_expand(SPECK_TYPE const K[static SPECK_KEY_LEN], SPECK_TYPE S[static SPECK_ROUNDS]);
void speck_encrypt(SPECK_TYPE const pt[static 2], SPECK_TYPE ct[static 2], SPECK_TYPE const K[static SPECK_ROUNDS]);
void speck_decrypt(SPECK_TYPE const ct[static 2], SPECK_TYPE pt[static 2], SPECK_TYPE const K[static SPECK_ROUNDS]);

void speck_encrypt_combined(SPECK_TYPE const pt[static 2], SPECK_TYPE ct[static 2], SPECK_TYPE const K[static SPECK_KEY_LEN]);
void speck_decrypt_combined(SPECK_TYPE const ct[static 2], SPECK_TYPE pt[static 2], SPECK_TYPE const K[static SPECK_KEY_LEN]);

int perm_speck_create(struct cperm_t *pt);
int perm_speck_destroy(struct cperm_t* pt);
int perm_speck_enc(struct cperm_t* perm, uint64_t pt, uint64_t* ct);
int perm_speck_dec(struct cperm_t* perm, uint64_t ct, uint64_t* pt);

#ifdef __cplusplus
}
#endif

#endif
