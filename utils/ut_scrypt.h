/*
 * Description: misc functions
 *     History: yang@haipo.me, 2016/03/15, create
 */

# ifndef _SCRYPT_H_
# define _SCRYPT_H_

# include <stdlib.h>
# include <stdint.h>

void scrypt_hash(const char *input, char *output);

# endif
