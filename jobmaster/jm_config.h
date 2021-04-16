/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/03, create
 */

# ifndef _JM_CONFIG_H_
# define _JM_CONFIG_H_

# include <stdio.h>
# include <error.h>
# include <errno.h>
# include <unistd.h>
# include <assert.h>
# include <inttypes.h>

# include "nw_svr.h"
# include "nw_clt.h"
# include "nw_timer.h"
# include "nw_state.h"
# include "ut_log.h"
# include "ut_sds.h"
# include "ut_cli.h"
# include "ut_coin.h"
# include "ut_misc.h"
# include "ut_config.h"
# include "ut_rpc_clt.h"
# include "ut_rpc_svr.h"
# include "ut_rpc_cmd.h"

struct coin_recipient {
    sds address;
    double percent;
};

struct settings {
    process_cfg         process;
    log_cfg             log;
    nw_svr_cfg          svr;
    cli_svr_cfg         cli;
    alert_cfg           alert;
    bool                has_brother;
    rpc_clt_cfg         brother;

    int                 blockmaster_count;
    char                **blockmasters;
    double              blockmaster_timeout;

    coin_rpc_cfg        main_coin;
    sds                 main_coin_recipient;
    struct coin_recipient *coin_recipients;
    int                 coin_recipient_count;
    double              coin_recipient_percents;
    uint32_t            main_block_version;
    int                 aux_coin_count;
    int32_t             aux_merkle_nonce;
    int32_t             aux_merkle_size;
    int32_t             aux_job_timeout;
    int32_t             rsk_job_interval;
    coin_rpc_cfg        *aux_coin;
    sds                 *aux_address;
    coin_rpc_cfg        *rsk_coin;
    coin_rpc_cfg        *vcash_coin;

    int                 job_rebroadcast_timeout;
    char                *pool_name;
    char                *coinbase_message;
    bool                coinbase_account;
    int                 spv_mining_timeout;
    http_svr_cfg        http_svr;
    bool                segwit_commitment_enabled;
};

extern struct settings settings;

int load_config(const char *path);

# endif

