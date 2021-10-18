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
#include "cycle.h"

int perm_cycle_create(struct cperm_t* perm) {
	struct cycle_data_t* cycle_data = calloc(1,sizeof(*cycle_data));
	if(!cycle_data) {
		cperm_errno = PERM_ERROR_NOMEM;
		return PERM_ERROR_NOMEM;
	}

	cycle_data->next = 0;
	cycle_data->count = 0;
	perm->mode_data = cycle_data;

	return 0;
}

int perm_cycle_get(struct cperm_t* perm, uint64_t pt, uint64_t* ct) {
	cperm_errno = PERM_ERROR_OP_NOT_SUPP;
	return PERM_ERROR_OP_NOT_SUPP;
}

int perm_cycle_next(struct cperm_t* perm, uint64_t* ct) {
	struct cycle_data_t* cycle_data = perm->mode_data;

	if(cycle_data->count >= perm->range) {
		cperm_errno = PERM_END;
		return PERM_END;
	}

	do {
		perm->cipher->enc(perm, cycle_data->next, ct);
		cycle_data->next++;
	}while(*ct >= perm->range);

	cycle_data->count++;

	return 0;
}

int perm_cycle_destroy(struct cperm_t* perm) {
	free(perm->mode_data);
	return 0;
}
