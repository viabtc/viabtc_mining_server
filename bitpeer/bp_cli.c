/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/04, create
 */

# include "bp_config.h"
# include "bp_cli.h"
# include "bp_peer.h"

static cli_svr *svr;

static sds on_cmd_update(const char *cmd, int argc, sds *argv)
{
    int ret = update_peer();
    if (ret < 0) {
        sds reply = sdsempty();
        reply = sdscatprintf(reply, "update_peer fail: %d\n", ret);
        return reply;
    }

    return sdsnew("success\n");
}

static sds on_cmd_status(const char *cmd, int argc, sds *argv)
{
    return get_peer_status();
}

int init_cli(void)
{
    svr = cli_svr_create(&settings.cli);
    if (svr == NULL) {
        return -__LINE__;
    }

    cli_svr_add_cmd(svr, "update", on_cmd_update);
    cli_svr_add_cmd(svr, "status", on_cmd_status);

    return 0;
}

