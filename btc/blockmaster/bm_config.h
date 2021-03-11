/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/18, create
 */

# ifndef _BM_CONFIG_H_
# define _BM_CONFIG_H_

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
# include "nw_job.h"
# include "ut_log.h"
# include "ut_sds.h"
# include "ut_cli.h"
# include "ut_coin.h"
# include "ut_misc.h"
# include "ut_pack.h"
# include "ut_config.h"
# include "ut_rpc_clt.h"
# include "ut_rpc_svr.h"
# include "ut_rpc_cmd.h"

# define TX_KEY_SIZE 8

struct settings {
    process_cfg         process;
    log_cfg             log;
    nw_svr_cfg          svr;
    cli_svr_cfg         cli;
    alert_cfg           alert;
    coin_rpc_cfg        coin;
    double              mempool_timeout;

    double              blockmaster_timeout;
    char                *request_auth;
    char                *blockmaster_url;
    json_t              *blockmaster_cfg;
    int                 blockmaster_update_interval;

    int                 bitpeer_count;
    char                **bitpeers;
    double              bitpeer_timeout;
    http_svr_cfg        http_svr;
};

extern struct settings settings;

int load_config(const char *path);

# endif

