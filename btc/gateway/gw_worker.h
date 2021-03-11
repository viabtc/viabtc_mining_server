/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/02, create
 */

# ifndef _GW_WORKER_H_
# define _GW_WORKER_H_

# include <stdbool.h>
# include <jansson.h>
# include "gw_job.h"
# include "ut_rpc.h"

int init_worker(int id);
int broadcast_job(struct job *job, bool clean_job);

sds get_clients_info(void);
json_t *get_clients_info_json();
void flush_worker_info(void);

int load_coinbase_message(sds filename);
sds list_coinbase_message();

# endif

