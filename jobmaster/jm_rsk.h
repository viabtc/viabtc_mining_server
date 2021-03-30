# ifndef _JM_RSK_H_
# define _JM_RSK_H_

# include <stdint.h>
# include <jansson.h>
# include "jm_config.h"

typedef struct rsk_coin_info {
    sds         rsk_name;
    int         height;
    int         mine_height;
    time_t      update_time;
    coin_rpc    *coin;
    json_t      *block;
} rsk_coin_info;

rsk_coin_info *rsk_info;

int init_rsk(void);
int submit_rsk_block(const char *block_hash, const char *block_header, const char *coinbase, const char *merkle_hashes, int blocktxn_count);

# endif

