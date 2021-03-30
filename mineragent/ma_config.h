/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/01, create
 */

# ifndef _LP_CONFIG_H_
# define _LP_CONFIG_H_

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

# define LISTENER_BIND   "seqpacket@/tmp/viabtc_btc_agent_listener.sock"

struct settings {
    process_cfg         process;
    log_cfg             log;
    nw_svr_cfg          svr;
    cli_svr_cfg         cli;

    char               *stratum_host;
    int                 stratum_port;
    int                 worker_num;
    int                 diff_min;
    int                 diff_max;
    int                 diff_default;
    int                 target_time;
    int                 retarget_time;
    int                 connect_timeout;
    int                 broadcast_timeout;
    int                 client_max_idle_time;
};

extern struct settings settings;

int load_config(const char *path);

# endif

