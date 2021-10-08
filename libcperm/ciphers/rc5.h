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


#ifndef RC5_H
#define RC5_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../cperm.h"
#include "rc5-16.h"

struct rc5_data {
	struct rc5_key key;
	uint32_t* blocks;
	uint32_t index;
};

int perm_rc5_create(struct cperm_t* pt);
int perm_rc5_destroy(struct cperm_t* pt);
int perm_rc5_enc(struct cperm_t* perm, uint64_t pt, uint64_t* ct);
int perm_rc5_dec(struct cperm_t* perm, uint64_t ct, uint64_t* pt);

#endif /* RC5_H */
