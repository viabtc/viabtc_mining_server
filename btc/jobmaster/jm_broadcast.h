/*
 * Description: 
 *     History: yang@haipo.me, 2016/06/06, create
 */

# ifndef _JM_BROADCAST_H_
# define _JM_BROADCAST_H_

# include <stddef.h>
# include "ut_rpc.h"

int init_broadcast(void);
int broadcast_block_msg(rpc_pkg *pkg);

# endif

