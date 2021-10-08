/*  ------------------------------------------------------------------------
	libcperm - A library for creating random permutations.
	Copyright (c) 2014, Lance Alt

	This file is part of libcperm.

	This library is free software: you can redistribute it and/or modify
	it under the terms of the GNU Lesser General Public License as published
	by the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Lesser General Public License for more details.
	
	You should have received a copy of the GNU Lesser General Public License
	along with this library.  If not, see <http://www.gnu.org/licenses/>.
	------------------------------------------------------------------------
*/


#ifndef PERM_INTERNAL_H
#define PERM_INTERNAL_H
/* Internal libperm header. Not to be included by programs using the library. */
#include <stdint.h>
#include "cperm.h"

/* Permutation mode and cipher function definitions */
typedef int (*ModeCreateFunc)(struct cperm_t*);
typedef int (*ModeNextFunc)(struct cperm_t*, uint64_t*);
typedef int (*ModeGetFunc)(struct cperm_t*, uint64_t, uint64_t*);
typedef int (*ModeDestroyFunc)(struct cperm_t*);

typedef int (*CipherCreateFunc)(struct cperm_t*);
typedef int (*CipherEncFunc)(struct cperm_t*, uint64_t, uint64_t*);
typedef int (*CipherDecFunc)(struct cperm_t*, uint64_t, uint64_t*);
typedef int (*CipherDestroyFunc)(struct cperm_t*);

/* libperm supports pluggable permutation modes and ciphers. They are defined by using
   ModeFuncs and CipherFuncs structures. */
struct ModeFuncs {
	PermMode mode;
	ModeCreateFunc create;
	ModeNextFunc next;
	ModeGetFunc get;
	ModeDestroyFunc destroy;
};

struct CipherFuncs {
	PermCipher algo;
	CipherCreateFunc create;
	CipherEncFunc enc;
	CipherDecFunc dec;
	CipherDestroyFunc destroy;
};

/* struct perm_t
	Main data structure containing the state for a single permutation. This structure is opaque to the
	user. It is returned from the perm_create() function and is passed as the first parameter to all the
	functions that operate on the permutation. Freed by calling the perm_destroy() function.
*/
struct cperm_t {
	uint8_t* key;					// Buffer containing the cipher key
	uint16_t key_len;				// Length of the key
	uint64_t range;					// Range (size) of the permutation
	uint64_t position;				// Position of the permutation (i.e. how many values have been read)
	void* mode_data;				// Data specific to the permutation mode used
	void* cipher_data;				// Data specific to the cipher used

	struct ModeFuncs* mode;			// Function pointers for the selected permutation mode
	struct CipherFuncs* cipher;		// Function pointers for the selected cipher
};

#endif /* PERM_INTERNAL_H */
