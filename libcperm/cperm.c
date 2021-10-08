/*  ------------------------------------------------------------------------
	libcperm - A library for creating random cpermutations.
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


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "cperm.h"
#include "cperm-internal.h"
#include "prefix.h"
#include "cycle.h"
#include "ciphers/rc5.h"
#include "ciphers/speck.h"

int cperm_errno = 0;

/* List of available cpermutation modes. Each mode has an identifier, and four functions. See ModeFuncs struct for description of the fields. */
static struct ModeFuncs available_modes[] = {
	{ PERM_MODE_PREFIX,		perm_prefix_create,	perm_prefix_next,	perm_prefix_get,	perm_prefix_destroy },
	{ PERM_MODE_CYCLE,		perm_cycle_create,	perm_cycle_next,	perm_cycle_get,		perm_cycle_destroy },
	{ PERM_MODE_ERROR,		NULL,					NULL }
};

/* List of available ciphers. Each cipher has an identifier, and four functions. See CipherFuncs struct for description of the fields. */
static struct CipherFuncs available_ciphers[] = {
	{ PERM_CIPHER_RC5,		perm_rc5_create,	perm_rc5_enc,		perm_rc5_dec,		perm_rc5_destroy },
	{ PERM_CIPHER_SPECK,		perm_speck_create,	perm_speck_enc,		perm_speck_dec,		perm_speck_destroy },
	{ PERM_CIPHER_ERROR,		NULL,			NULL,   NULL },
};

struct cperm_t* cperm_create(uint64_t range, PermMode m, PermCipher a, uint8_t* key, int key_len) {
	struct cperm_t* perm = calloc(sizeof(*perm), 1);
	if(!perm) {
		cperm_errno = PERM_ERROR_NOMEM;
		return NULL;
	}

	perm->range = range;

	/* Locate the selected mode and initialize function pointers */
	struct ModeFuncs* mf = available_modes;
	while(mf->mode != PERM_MODE_ERROR) {
		if(mf->mode == m) {
			perm->mode = mf;
			break;
		}
		mf++;
	}
	if(perm->mode == NULL) {
		free(perm);
		cperm_errno = PERM_ERROR_MODE_NOT_SUPP;
		return NULL;
	}

	/* Locate the selected cipher and initialize function pointers */
	struct CipherFuncs* cf = available_ciphers;
	while(cf->algo != PERM_CIPHER_ERROR) {
		if(cf->algo == a) {
			perm->cipher = cf;
			break;
		}
		cf++;
	}

	/* Set the cipher key */
	cperm_set_key(perm, key, key_len);

	/* Initialize the cipher */
	if(0 != perm->cipher->create(perm)) {
		free(perm);
		return NULL;
	}

	/* Initialize the cpermutation mode */
	if(0 != perm->mode->create(perm)) {
		perm->cipher->destroy(perm);
		free(perm);
		return NULL;
	}

	return perm;
}

int cperm_set_key(struct cperm_t* perm, const unsigned char* key, uint16_t length) {
	if(!perm) { return PERM_ERROR_BAD_HANDLE; }

	if(perm->cipher) {
		perm->cipher->destroy(perm);
	}
	
	perm->key = malloc(length);
	memcpy(perm->key, key, length);
	perm->key_len = length;

	return 0;
}

void cperm_destroy(struct cperm_t* perm) {
	if(perm) {
		perm->mode->destroy(perm);
		perm->cipher->destroy(perm);
		if(perm->key) {
			free(perm->key);
		}
		free(perm);
	}
}

int cperm_next(struct cperm_t* perm, uint64_t* ct) {
	if(!perm) { return PERM_ERROR_BAD_HANDLE; }
	perm->position++;
	return perm->mode->next(perm, ct);
}

int cperm_enc(struct cperm_t* perm, uint64_t pt, uint64_t* ct) {
	if(!perm) { return PERM_ERROR_BAD_HANDLE; }
	return perm->mode->get(perm, pt, ct);
}

uint64_t cperm_dec(struct cperm_t* cperm, uint64_t pt) {
	return 0;
}

int cperm_get_last_error() {
	return cperm_errno;
}

int cperm_reset(struct cperm_t* perm) {
	if(!perm) { return PERM_ERROR_BAD_HANDLE; }

	perm->mode->destroy(perm);
	perm->mode->create(perm);
	return 1;
}

uint64_t cperm_get_range(const struct cperm_t* perm) {
	if(!perm) { return 0; }
	return perm->range;
}

uint64_t cperm_get_position(const struct cperm_t* perm) {
	if(!perm) { return 0; }
	return perm->position;
}


