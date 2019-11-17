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

/**
 * @file perm.h
 * @author Lance Alt
 * @date 24 July 2014
 * @brief libperm API
 * 
 */
#ifndef PERM_H
#define PERM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// General errors
#define PERM_ERROR_UNKNOWN			-1
#define PERM_ERROR_BAD_HANDLE		-2		// cperm_t was not valid
#define PERM_ERROR_NOMEM			-3		// failed to allocate memory
#define PERM_ERROR_RANGE			-4		// requested item was outside permutation range
#define PERM_END					-5		// when calling next(), at the end of the permutation

// Key related errors
#define PERM_ERROR_NOKEY			-10		// no key was set
#define PERM_ERROR_BAD_KEY_LENGTH	-11		// key was incorrect length for particular cipher

// Cipher related errors
#define PERM_ERROR_CIPHER_NOT_SUPP	-20		// cipher not supported

// Mode related errors
#define PERM_ERROR_MODE_NOT_SUPP	-30		// mode not supported
#define PERM_ERROR_OP_NOT_SUPP		-31		// operation not supported in this mode

/**
 * @brief Permutation mode to use.
 *
 * Enumerate to select which type of permutation mode to use. Available options are:
 */
typedef enum {	PERM_MODE_ERROR = -1,
				PERM_MODE_AUTO,				/**< Automatically select the mode to use based on permutation size */
				PERM_MODE_PREFIX,			/**< Use prefix cipher mode */
				PERM_MODE_CYCLE,			/**< Use cycle walking mode */
				PERM_MODE_FEISTEL			/**< Use Feistel mode (currently not implemented) */
} PermMode;

typedef enum {	PERM_CIPHER_ERROR = -1,
				PERM_CIPHER_AUTO,			// Automatically select cipher to user (only RC5 is currently implemented)
				PERM_CIPHER_RC5,			// Use the RC5 cipher
				PERM_CIPHER_SPECK			// Use the Speck cipher
} PermCipher;

struct ccperm_t;

extern int cperm_errno;

/**
 * @brief Create a new permutation.
 *
 * Create a new permutation of the given range. The permutation will contain items between
 * 0 and @c range. The permutation mode can be selected using the @mode parameter or selected
 * automatically using the @c PERM_MODE_AUTO option. The cipher to use is selected using the
 * @c cipher parameter or automatically selected using the @c PERM_CIPHER_AUTO option.
 *
 * @param range Size of the permutation. Maximum of 2^32.
 * @param mode Permutation generation mode to use.
 * @param cipher Cipher to use.
 * @param key Cipher key.
 * @param key_len Length of the cipher key passed in @p key.
 *
 * @return Returns a pointer to @c cperm_t or error.
 */
struct cperm_t* cperm_create(uint32_t range, PermMode m, PermCipher a, uint8_t* key, int key_len);

/**
 * @brief Destroy a permutation object.
 *
 * All resources used by the permutation object will be freed and the object will become
 * invalid.
 *
 * @param p Permutation object to destroy.
 */
void cperm_destroy(struct cperm_t* p);

int cperm_set_key(struct cperm_t* perm, const unsigned char* key, uint16_t length);

/**
 * @brief Get the next item in the permutation.
 *
 * Newly created permutations start at index zero. Each call to @c perm_next returns the
 * next permutation item in succession until the end of permutation is reached.
 *
 * @param p Permutation object
 * @param ct Pointer to an integer to store the next permutation value
 *
 * @return 0 on success or @c PERM_END when there are no more items in the permutation.
 */
int cperm_next(struct cperm_t* p, uint32_t* ct);

/**
 * @brief Encodes an index to its permuted value.
 *
 * Note: This API call is not supported on all permutation modes. At present, this
 * function is only supported when using @c PERM_MODE_PREFIX. Calling this function
 * when using a different mode will return @c PERM_ERROR_OP_NOT_SUPP.
 *
 * @param p The permutation object
 * @param pt Index within the permutation
 * @param ct Pointer to an integer to store the permuted value
 *
 * @return 0 on success or error code on failure.
 */
int cperm_enc(struct cperm_t* perm, uint32_t pt, uint32_t* ct);

/**
 * @brief Returns the error status of the last API function.
 *
 * Most API calls return an error code directly. Some functions however, do not return
 * specific errors and must be checked explicitly using this function. The following
 * functions must be explicitly checked for error conditions:
 *   - @c perm_create
 *   - @c perm_get_position
 *   - @c perm_get_range 
 *
 * @return Last API error or PERM_OK if the last API call was successful.
 */
int cperm_get_last_error();

/**
 * @brief Returns the range of a permutation object.
 *
 * @param p The permutation object
 *
 * @return Length of the permutation or 0 on error.
 */
uint32_t cperm_get_range(const struct cperm_t* p);

/**
 * @brief Returns the current position of a permutation object.
 *
 * @param p The permutation object
 *
 * @return Current position of the permutation or 0 on error.
 */
uint32_t cperm_get_position(const struct cperm_t* p);

/**
 * @brief Resets the position of the permutation back to 0.
 *
 * @param p The permutation object
 *
 * @return 0 on success or @c PERM_ERROR_BAD_HANDLE if the object is invalid.
 */
int cperm_reset(struct cperm_t* perm);

#ifdef __cplusplus
};
#endif

#endif /* PERM_H */
