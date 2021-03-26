/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/02, create
 */

# ifndef _GW_WORKER_H_
# define _GW_WORKER_H_

# include <stdbool.h>
# include <jansson.h>
# include "ma_job.h"

extern uint32_t worker_id;

int init_worker(void);
int broadcast_job(struct job *job, bool clean_job);
int close_all_connection(void);
int submit_sync_all(void);
sds get_clients_info(void);
int get_extra_nonce_size();

# endif

