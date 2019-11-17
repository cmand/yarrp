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


#ifndef PREFIX_H
#define PREFIX_H

#include <stdint.h>
#include "cperm.h"

struct prefix_element {
	uint32_t pt;
	uint32_t ct;
};

struct prefix_data_t {
	struct prefix_element* vector;
	uint32_t next;
};

int perm_prefix_create(struct cperm_t* perm);
int perm_prefix_get(struct cperm_t* perm, uint32_t pt, uint32_t* ct);
int perm_prefix_next(struct cperm_t* perm, uint32_t* ct);
int perm_prefix_destroy(struct cperm_t* perm);

#endif /* PREFIX_H */
