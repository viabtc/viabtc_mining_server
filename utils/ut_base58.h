/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/03, create
 */

# ifndef _UT_BASE58_H_
# define _UT_BASE58_H_

# include <stdint.h>
# include <stddef.h>

# include "ut_sds.h"

sds base58_decode(const char *str);
sds base58_encode(const char *mem, size_t len);

sds address2sig(const char *address);
sds sig2address(uint8_t version, const char *sig);

sds zec_address2sig(const char *address);
sds zec_sig2address(uint8_t prefix, uint8_t version, const char *sig);

# endif

