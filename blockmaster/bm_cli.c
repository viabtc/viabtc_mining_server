/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/19, create
 */

# include "bm_cli.h"
# include "bm_config.h"
# include "bm_block.h"
# include "bm_tx.h"

static cli_svr *svr;

static sds on_cmd_blocknotify(const char *cmd, int argc, sds *argv)
{
    on_blocknotify();
    log_info("cmd: %s", cmd);
    return sdsnew("ok\n");
}

static sds on_cmd_tx_info(const char *cmd, int argc, sds *argv)
{
    return get_tx_info();
}

int init_cli(void)
{
    svr = cli_svr_create(&settings.cli);
    if (svr == NULL) {
        return -__LINE__;
    }

    cli_svr_add_cmd(svr, "blocknotify", on_cmd_blocknotify);
    cli_svr_add_cmd(svr, "tx_info", on_cmd_tx_info);

    return 0;
}

