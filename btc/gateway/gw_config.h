/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/01, create
 */

# ifndef _GW_CONFIG_H_
# define _GW_CONFIG_H_

# include <stdio.h>
# include <error.h>
# include <errno.h>
# include <ctype.h>
# include <unistd.h>
# include <assert.h>
# include <inttypes.h>
# include <math.h>

# include "nw_svr.h"
# include "nw_clt.h"
# include "nw_timer.h"
# include "nw_state.h"
# include "ut_log.h"
# include "ut_sds.h"
# include "ut_cli.h"
# include "ut_redis.h"
# include "ut_misc.h"
# include "ut_config.h"
# include "ut_rpc_clt.h"
# include "ut_rpc_svr.h"
# include "ut_rpc_cmd.h"
# include "ut_http_svr.h"

# define GW_LISTENER_BIND   "seqpacket@/tmp/gateway_listener.sock"
# define GW_AGGREGATOR_BIND "stream@/tmp/gateway_aggregator.sock"

# define VARDIFF_RETARGET_SHARE 30

struct settings {
    process_cfg         process;
    log_cfg             log;
    nw_svr_cfg          svr;
    http_svr_cfg        http_svr;
    nw_svr_cfg          monitor;
    rpc_clt_cfg         job;
    rpc_clt_cfg         writer;
    cli_svr_cfg         cli;
    alert_cfg           alert;

    char                *coin;
    char                *queue;
    char                *coinbase_message_file;
    int                 worker_id;
    int                 worker_num;
    int                 diff_min;
    int                 diff_max;
    int                 diff_default;
    int                 target_time;
    int                 retarget_time;
    int                 client_max_idle_time;
};

extern struct settings settings;

int load_config(const char *path);

# endif

