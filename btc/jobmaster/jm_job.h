/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/03, create
 */

# ifndef _JM_JOB_H_
# define _JM_JOB_H_

# include <stdint.h>
# include "nw_ses.h"
# include "ut_sds.h"

int init_job(void);
int send_curr_job(nw_ses *ses);

int set_coinbase_message(sds msg);
sds get_coinbase_message(void);
uint32_t get_current_height();
int clear_coinbase_message(void);

int on_main_blocknotify(void);
int on_height_update(int height, uint32_t curtime, uint32_t nbits, const char *target, const char *prevhash);
int on_aux_update(void);
int on_rsk_update(void);
int on_vcash_update(void);

int on_found_block_main(sds job_id, sds block_head, sds coinbase);
int on_found_block_aux(sds job_id, sds block_head, sds coinbase, const char *aux_name);

# endif

