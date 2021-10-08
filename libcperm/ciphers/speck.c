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
#include "speck.h"

#if WORDSIZE == 24
  // rotates for word size n=24 bits
  #define ROR(x, r) ((x >> r) | (x << (24 - r))&MASK24)&MASK24
  #define ROL(x, r) ((x << r) | (x >> (24 - r))&MASK24)&MASK24
#elif WORDSIZE == 48
  #define ROR(x, r) ((x >> r) | (x << (48 - r))&MASK48)&MASK48
  #define ROL(x, r) ((x << r) | (x >> (48 - r))&MASK48)&MASK48
#else
  #define ROR(x, r) ((x >> r) | (x << ((sizeof(SPECK_TYPE) * 8) - r)))
  #define ROL(x, r) ((x << r) | (x >> ((sizeof(SPECK_TYPE) * 8) - r)))
#endif

#ifdef SPECK_32_64
  #define R(x, y, k) (x = ROR(x, 7), x += y, x ^= k, y = ROL(y, 2), y ^= x)
  #define RR(x, y, k) (y ^= x, y = ROR(y, 2), x ^= k, x -= y, x = ROL(x, 7))
#else
  #if WORDSIZE == 24
  #define R(x, y, k) (x = ROR(x, 8), x = (x + y)&MASK24, x ^= k, y = ROL(y, 3), y ^= x)
  #define RR(x, y, k) (y ^= x, y = ROR(y, 3), x ^= k, x = (x - y)&MASK24, x = ROL(x, 8))
  #elif WORDSIZE == 48
  #define R(x, y, k) (x = ROR(x, 8), x = (x + y)&MASK48, x ^= k, y = ROL(y, 3), y ^= x)
  #define RR(x, y, k) (y ^= x, y = ROR(y, 3), x ^= k, x = (x - y)&MASK48, x = ROL(x, 8))
  #else
  #define R(x, y, k) (x = ROR(x, 8), x += y, x ^= k, y = ROL(y, 3), y ^= x)
  #define RR(x, y, k) (y ^= x, y = ROR(y, 3), x ^= k, x -= y, x = ROL(x, 8))
  #endif
#endif

struct speck_data {
#ifdef SPECK_32_64
  uint16_t key[4];
  SPECK_TYPE exp[SPECK_ROUNDS];
#endif
};

int perm_speck_create(struct cperm_t *pt) {
    struct speck_data *d;

    if(pt->key_len != 8) {
        return PERM_ERROR_BAD_KEY_LENGTH;
    }

    d = malloc(sizeof(*d));
    memcpy(&d->key, pt->key, pt->key_len);
    speck_expand(d->key, d->exp);

    pt->cipher_data = d;

    return 0;
}

int perm_speck_destroy(struct cperm_t* pt) {
    free(pt->cipher_data);
    return 0;
}

int perm_speck_enc(struct cperm_t* perm, uint64_t pt, uint64_t* ct) {
    struct speck_data* d = perm->cipher_data;

    SPECK_TYPE *plain = (SPECK_TYPE *) &pt;
    SPECK_TYPE *buffer = (SPECK_TYPE *) ct;
    
    speck_encrypt(plain, buffer, d->exp);
    return 0;
}

int perm_speck_dec(struct cperm_t* perm, uint64_t ct, uint64_t* pt) {
    struct speck_data* d = perm->cipher_data;

    SPECK_TYPE *enc = (SPECK_TYPE *) &ct;
    SPECK_TYPE *buffer = (SPECK_TYPE *) pt;

    speck_decrypt(enc, buffer, d->exp);
    return 0;
}

void speck_expand(SPECK_TYPE const K[static SPECK_KEY_LEN], SPECK_TYPE S[static SPECK_ROUNDS])
{
  SPECK_TYPE i, b = K[0];
  SPECK_TYPE a[SPECK_KEY_LEN - 1];

  for (i = 0; i < (SPECK_KEY_LEN - 1); i++)
  {
    a[i] = K[i + 1];
  }
  S[0] = b;  
  for (i = 0; i < SPECK_ROUNDS - 1; i++) {
    R(a[i % (SPECK_KEY_LEN - 1)], b, i);
    S[i + 1] = b;
  }
}

void speck_encrypt(SPECK_TYPE const pt[static 2], SPECK_TYPE ct[static 2], SPECK_TYPE const K[static SPECK_ROUNDS])
{
  SPECK_TYPE i;
  ct[0]=pt[0]; ct[1]=pt[1];

  for(i = 0; i < SPECK_ROUNDS; i++){
    R(ct[1], ct[0], K[i]);
  }
}

void speck_decrypt(SPECK_TYPE const ct[static 2], SPECK_TYPE pt[static 2], SPECK_TYPE const K[static SPECK_ROUNDS])
{
  SPECK_TYPE i;
  pt[0]=ct[0]; pt[1]=ct[1];

  for(i = 0; i < SPECK_ROUNDS; i++){
    RR(pt[1], pt[0], K[(SPECK_ROUNDS - 1) - i]);
  }
}

void speck_encrypt_combined(SPECK_TYPE const pt[static 2], SPECK_TYPE ct[static 2], SPECK_TYPE const K[static SPECK_KEY_LEN])
{
  SPECK_TYPE i, b = K[0];
  SPECK_TYPE a[SPECK_KEY_LEN - 1];
  ct[0]=pt[0]; ct[1]=pt[1];

  for (i = 0; i < (SPECK_KEY_LEN - 1); i++)
  {
    a[i] = K[i + 1];
  }

  R(ct[1], ct[0], b);
  for(i = 0; i < SPECK_ROUNDS - 1; i++){
    R(a[i % (SPECK_KEY_LEN - 1)], b, i);
    R(ct[1], ct[0], b);
  }
}

void speck_decrypt_combined(SPECK_TYPE const ct[static 2], SPECK_TYPE pt[static 2], SPECK_TYPE const K[static SPECK_KEY_LEN])
{
  int i;
  SPECK_TYPE b = K[0];
  SPECK_TYPE a[SPECK_KEY_LEN - 1];
  pt[0]=ct[0]; pt[1]=ct[1];

  for (i = 0; i < (SPECK_KEY_LEN - 1); i++)
  {
    a[i] = K[i + 1];
  }

  for (i = 0; i < SPECK_ROUNDS - 1; i++)
  {
    R(a[i % (SPECK_KEY_LEN - 1)], b, i);
  }

  for(i = 0; i < SPECK_ROUNDS; i++){
    RR(pt[1], pt[0], b);
    RR(a[((SPECK_ROUNDS - 2) - i) % (SPECK_KEY_LEN - 1)], b, ((SPECK_ROUNDS - 2) - i));
  }
}

#ifdef TEST

#include <string.h>
#include <stdio.h>

int main(int argc, char** argv)
{
#ifdef SPECK_32_64
  uint16_t key[4] = {0x0100, 0x0908, 0x1110, 0x1918};
  uint16_t plain[2] = {0x694c, 0x6574};
  uint16_t enc[2] = {0x42f2, 0xa868};
#endif

#ifdef SPECK_48_72
  uint32_t key[3] = {0x020100, 0x0a0908, 0x121110};
  uint32_t plain[2] = {0x6c6172, 0x20796c};
  uint32_t enc[2] = {0x385adc, 0xc049a5};
#endif

#ifdef SPECK_48_96
  uint32_t key[4] = {0x020100, 0x0a0908, 0x121110, 0x1a1918};
  uint32_t plain[2] = {0x696874, 0x6d2073};
  uint32_t enc[2] = {0xb6445d, 0x735e10};
#endif

#ifdef SPECK_64_128
  uint32_t key[4] = {0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918};
  uint32_t plain[2] = {0x7475432d, 0x3b726574};
  uint32_t enc[2] = {0x454e028b, 0x8c6fa548};
#endif

#ifdef SPECK_96_96
  uint64_t key[2] = {0x050403020100, 0x0d0c0b0a0908};
  uint64_t plain[2] = {0x656761737520, 0x65776f68202c};
  uint64_t enc[2] = {0x62bdde8f79aa, 0x9e4d09ab7178};
#endif

#ifdef SPECK_96_144
  uint64_t key[3] = {0x050403020100, 0x0d0c0b0a0908, 0x151413121110};
  uint64_t plain[2] = {0x69202c726576, 0x656d6974206e};
  uint64_t enc[2] = {0x7ae440252ee6, 0x2bf31072228a};
#endif

#ifdef SPECK_128_256
  uint64_t key[4] = {0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110, 0x1f1e1d1c1b1a1918};
  uint64_t plain[2] = {0x202e72656e6f6f70, 0x65736f6874206e49};
  uint64_t enc[2] = {0x4eeeb48d9c188f43, 0x4109010405c0f53e};
#endif

  SPECK_TYPE buffer[2] = {0};
  SPECK_TYPE exp[SPECK_ROUNDS];

  speck_expand(key, exp);

#ifdef TEST_COMBINED
  speck_encrypt_combined(plain, buffer, key);
#else
  speck_encrypt(plain, buffer, exp);
#endif
  if (memcmp(buffer, enc, sizeof(enc))) {
    printf("encryption failed\n");
    return 1;
  }
#ifdef TEST_COMBINED
  speck_decrypt_combined(enc, buffer, key);
#else
  speck_decrypt(enc, buffer, exp);
#endif
  if (memcmp(buffer, plain, sizeof(enc))) {
    printf("decryption failed\n");
    return 1;
  }
  printf("OK\n");
  return 0;
}

#endif
