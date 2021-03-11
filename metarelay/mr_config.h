/*
 * Description: 
 *     History: yang@haipo.me, 2016/12/07, create
 */

# ifndef _MR_RELAY_H_
# define _MR_RELAY_H_

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

struct settings {
    process_cfg         process;
    log_cfg             log;
    alert_cfg           alert;
    nw_svr_cfg          svr;
    nw_svr_cfg          monitor;
    rpc_clt_cfg         writer;
    char                *queue;
    bool                spilt;
    rpc_clt_cfg         writer2;
    char                *queue2;
    int                 trust_count;
    char                **trust_list;
};

extern struct settings settings;

int load_config(const char *path);

# endif

