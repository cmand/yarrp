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


#include <stdint.h>
#include <stdlib.h>

#include "cperm.h"
#include "cperm-internal.h"
#include "feistel.h"
#include "ciphers/rc5.h"

int perm_feistel_create(struct perm_t* perm) {
	struct feistel_data_t* feistel_data = malloc(sizeof(*feistel_data));
	if(!feistel_data) {
		perm_errno = PERM_ERROR_NOMEM;
		return -1;
	}

	feistel_data->next = 0;
	feistel_data->count = 0;
	perm->mode_data = feistel_data;

	return 0;
}

int perm_feistel_get(struct perm_t* perm, uint32_t pt, uint32_t* ct) {
	perm_errno = PERM_ERROR_RANGE;
	return -1;
}

int perm_feistel_next(struct perm_t* perm, uint32_t* ct) {
	struct feistel_data_t* feistel_data = perm->mode_data;

	c = fe(r, a, b);

	if(feistel_data->count >= perm->range) {
		perm_errno = PERM_END;
		return PERM_END;
	}

	do {
		perm_rc5_enc(perm, feistel_data->next, ct);
		feistel_data->next++;
	}while(*ct >= perm->range);

	feistel_data->count++;

	return 0;
}

int perm_feistel_destroy(struct perm_t* perm) {
	free(perm->mode_data);
	return 0;
}

uint32_t fe(int r, int a, int b, int m) {
	int L = m % a;
	int R = m / a;

	for(int j = 0; j < r; j++) {
		if(j % 2 == 1) {
			tmp = L + F(R) % a;
		} else {
			tmp = L + F(R) % b;
		}
		L = R;
		R = tmp;
	}
	if(r % 2 == 1) {
		return a * L + R;
	} else {
		return a * R + L;
	}
}

uint32_t F(uint32_t pt) {
	uint32_t ct;
	perm->cipher->enc(perm, &v, &ct);
	return ct;
}
