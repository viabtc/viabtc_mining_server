/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/04, create
 */

# ifndef _GW_JOB_H_
# define _GW_JOB_H_

# include <stdint.h>
# include <stdbool.h>
# include <jansson.h>
# include "ut_sds.h"

typedef struct aux_meta {
    char aux_target[32];
    sds  aux_hash;
    sds  aux_name;
} aux_meta;

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
    size_t      merkle_branch_count;
    sds        *merkle_branch;
    json_t     *merkle_json;
    sds         name;
    double      block_diff;

    /* aux blockchain */
    int         aux_count;
    aux_meta    *auxes;

    sds         job_raw;
};

int init_job(void);

struct job *get_curr_job(void);
struct job *find_job(const char *job_id);
sds get_real_coinbase1(struct job *job, char *user, uint32_t worker_id, uint32_t nonce_id, const char *coinbase_message);
sds get_real_coinbase1_ext(struct job *job, char *user, uint32_t agent_id, uint32_t nonce_id, const char *coinbase_message);

double get_share_difficulty(const char *block_hash);
bool is_share_exist(const char *block_hash);

bool is_valid_main_block(struct job *job, const char *header_hash);
int on_found_block(const char *job_id, const char *type, const char *name, const char *hash, const char *block_head, const sds coinbase);

bool is_ip_banned(const char *ip);

# endif

