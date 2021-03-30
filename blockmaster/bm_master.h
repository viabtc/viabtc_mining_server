/*
 * Description: 
 *     History: yang@haipo.me, 2016/06/06, create
 */

# ifndef _BM_MASTER_H_
# define _BM_MASTER_H_

# include <stddef.h>
# include "ut_rpc.h"

int init_master(void);
int broadcast_master_msg(rpc_pkg *pkg);
int get_blockmaster_connection_num(void);

# endif

