/*
 * Description: 
 *     History: yang@haipo.me, 2016/06/27, create
 */

# ifndef _BP_CONFIG_H_
# define _BP_CONFIG_H_

# include <stdio.h>
# include <error.h>
# include <errno.h>
# include <ctype.h>
# include <unistd.h>
# include <assert.h>
# include <inttypes.h>

# include "nw_svr.h"
# include "nw_clt.h"
# include "nw_job.h"
# include "nw_timer.h"
# include "nw_state.h"
# include "ut_log.h"
# include "ut_sds.h"
# include "ut_cli.h"
# include "ut_misc.h"
# include "ut_config.h"
# include "ut_rpc_clt.h"
# include "ut_rpc_svr.h"
# include "ut_rpc_cmd.h"

struct settings {
    process_cfg         process;
    log_cfg             log;
    alert_cfg           alert;
    nw_svr_cfg          svr;
    cli_svr_cfg         cli;
    coin_rpc_cfg        coin;

    char                *peer_config_path;
    int                 reconnect_timeout;
    int                 broadcast_limit;
    sds                 start_string;

    char                *request_auth;
    char                *jobmaster_url;
    json_t              *jobmaster_cfg;
    inetv4_list         *jobmaster;
    int                 jobmaster_update_interval;
    http_svr_cfg        http_svr;
};

extern struct settings settings;

int load_config(const char *path);

# endif

