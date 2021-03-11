/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/04, create
 */

# ifndef _LP_JOB_H_
# define _LP_JOB_H_

# include <stdint.h>
# include <stdbool.h>
# include <jansson.h>
# include "ut_sds.h"

struct job {
    char        job_id[5];
    uint16_t    job_id_num;
    uint32_t    version;
    char        version_hex[9];
    uint32_t    curtime;
    char        curtime_hex[9];
    uint32_t    nbits;
    char        nbits_hex[9];
    uint32_t    height;
    char        prevhash[32];
    char        prevhash_raw[32];
    sds         prevhash_hex;
    char        target[32];
    sds         pool_name;
    sds         coinbase_message;
    bool        coinbase_account;
    sds         coinbaseaux_bin;
    sds         coinbase1_bin;
    sds         coinbase2_bin;
    sds         coinbase2_hex;
    sds        *merkle_branch;
    size_t      merkle_branch_count;
    json_t     *merkle_json;
    sds         name;
    double      block_diff;

    /* aux blockchain */
    bool        has_aux_coin;
    char        aux_target[32];
    sds         aux_hash;
    sds         aux_name;

    bool        is_fake;
};

int init_job(void);

struct job *get_curr_job(void);
struct job *find_job(const char *job_id);

sds get_real_coinbase1(struct job *job, char *user, uint32_t nonce_id, const char *coinbase_message);
double get_share_difficulty(const char *block_hash);
int is_stratum_ok(void);

int submit_sync(uint32_t miner_id, uint32_t nonce_id, char *extra_nonce1, int difficulty);
int submit_share(uint32_t miner_id, json_t *share, char *coinbase_message);
int submit_share_v2(uint32_t miner_id, json_t *share, uint32_t version_mask_svr, uint32_t version_mask_miner, uint32_t version_mask, char *coinbase_message);
int submit_event(const char *user, const char *worker, const char *event);
int submit_status(time_t timestamp, int connections);

int send_data(const char *data, size_t size);

# endif

