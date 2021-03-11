/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/03, create
 */

# ifndef _JM_SERVER_H_
# define _JM_SERVER_H_

# include <stddef.h>
# include <jansson.h>
# include "ut_rpc.h"

int init_server(void);
int close_all_connection(void);
int broadcast_msg(rpc_pkg *pkg);
int broadcast_add_ban_ip(json_t *ip_list, int limit);
int broadcast_del_ban_ip(json_t *ip_list);
sds get_ban_ip_list(void);

# endif

