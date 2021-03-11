/*
 * Description: 
 *     History: yang@haipo.me, 2016/06/06, create
 */

# ifndef _BM_PEER_H_
# define _BM_PEER_H_

# include <stddef.h>
# include "ut_rpc.h"

int init_peer(void);
int broadcast_peer_msg(rpc_pkg *pkg);

# endif

