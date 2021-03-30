/*
 * Description: 
 *     History: yang@haipo.me, 2016/06/22, create
 */

# ifndef _PB_CONFIG_H_
# define _PB_CONFIG_H_

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
# include "ut_redis.h"
# include "ut_misc.h"
# include "ut_config.h"

# define CMD_HEIGHT_UPDATE  4

struct pool_cfg {
    char *name;
    char *host;
    int   port;
    char *user;
    char *pass;
    bool  is_notify;
    bool  is_self;
};

struct settings {
    process_cfg         process;
    log_cfg             log;
    alert_cfg           alert;
    inetv4_list         *jobmaster;
    cli_svr_cfg         cli;
    int                 pool_count;
    double              max_delay;

    struct pool_cfg     *pool_list;
    bool                is_notify;
    int                 jobmaster_update_interval;
    char                *request_auth;
    char                *jobmaster_url;
    json_t              *jobmaster_cfg;
};

extern struct settings settings;
int load_config(const char *path);

# endif

