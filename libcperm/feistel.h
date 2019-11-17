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


#ifndef FEISTEL_H
#define FEISTEL_H

#include <stdint.h>
#include "perm.h"

struct feistel_data_t {
	uint32_t next;
	uint32_t count;
};

int perm_feistel_create(struct perm_t* perm);
int perm_feistel_get(struct perm_t* perm, uint32_t pt, uint32_t* ct);
int perm_feistel_next(struct perm_t* perm, uint32_t* ct);
int perm_feistel_destroy(struct perm_t* perm);

#endif /* FEISTEL_H */
