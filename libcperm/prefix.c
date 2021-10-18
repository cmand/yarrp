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
#include "prefix.h"

static int prefix_element_sort(const void* a, const void* b) {
	const struct prefix_element* ea = a;
	const struct prefix_element* eb = b;

	if(ea->ct < eb->ct) return -1;
	else                return  1;
}

int perm_prefix_create(struct cperm_t* perm) {
	struct prefix_data_t* prefix_data = calloc(1,sizeof(*prefix_data));
	if(!prefix_data) {
		cperm_errno = PERM_ERROR_NOMEM;
		return PERM_ERROR_NOMEM;
	}

	struct prefix_element* vect = calloc(perm->range, sizeof(struct prefix_element));
	if(!vect) {
		free(prefix_data);
		cperm_errno = PERM_ERROR_NOMEM;
		return PERM_ERROR_NOMEM;
	}

	for(uint64_t i = 0; i < perm->range; i++) {
		perm->cipher->enc(perm, i, &vect[i].ct);
		vect[i].pt = i;
	}

	qsort(vect, perm->range, sizeof(struct prefix_element), prefix_element_sort);

	prefix_data->vector = vect;
	prefix_data->next = 0;
	perm->mode_data = prefix_data;

	return 0;
}

int perm_prefix_get(struct cperm_t* perm, uint64_t pt, uint64_t* ct) {
	struct prefix_data_t* prefix_data = perm->mode_data;

	if(pt < perm->range) {
		*ct = prefix_data->vector[pt].pt;
		return 0;
	}

	cperm_errno = PERM_ERROR_RANGE;
	return PERM_ERROR_RANGE;
}

int perm_prefix_next(struct cperm_t* perm, uint64_t* ct) {
	struct prefix_data_t* prefix_data = perm->mode_data;

	if(prefix_data->next < perm->range) {
		*ct = prefix_data->vector[prefix_data->next++].pt;
		return 0;
	}

	cperm_errno = PERM_END;
	return PERM_END;
}

int perm_prefix_destroy(struct cperm_t* perm) {
	struct prefix_data_t* prefix_data = perm->mode_data;
	free(prefix_data->vector);
	free(prefix_data);
	return 0;
}
