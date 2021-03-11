/*
 * Description: 
 *     History: yang@haipo.me, 2016/12/03, create
 */

# ifndef _MW_CONFIG_H_
# define _MW_CONFIG_H_

# include <stdio.h>
# include <error.h>
# include <errno.h>
# include <ctype.h>
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
# include "ut_redis.h"
# include "ut_misc.h"
# include "ut_config.h"
# include "ut_rpc_clt.h"
# include "ut_rpc_svr.h"

# define MW_WORKER_BIND "stream@/tmp/metawriter_worker.sock"
# define MAX_USER_NAME_LEN          64
# define MAX_WORKER_NAME_LEN        64
# define WORKER_SAVE_TIME           3600

struct settings {
    process_cfg         process;
    log_cfg             log;
    nw_svr_cfg          svr;
    nw_svr_cfg          monitor;
    cli_svr_cfg         cli;
    alert_cfg           alert;
    redis_cfg           redis;
    bool                has_brother;
    rpc_clt_cfg         brother;
    int                 key_expire;
    int                 dup_timeout;
    char                *trust_file;
};

extern struct settings settings;

int load_config(const char *path);

# endif

