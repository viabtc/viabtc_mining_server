/*
 * Description: job master server
 *     History: yangxiaoqiang@viabtc.com, 2020/06/10, create
 */

# ifndef _JM_VCASH_H_
# define _JM_VCASH_H_

# include <stdint.h>
# include <jansson.h>
# include "jm_config.h"

typedef struct vcash_coin_info {
    sds         vcash_name;
    int         height;
    time_t      update_time;
    coin_rpc    *coin;
    json_t      *block;
} vcash_coin_info;

vcash_coin_info *vcash_info;

int init_vcash(void);
int submit_vcash_block(const char *block_hash, const char *block_header, const char *coinbase, const char *merkle_hashes);

# endif

