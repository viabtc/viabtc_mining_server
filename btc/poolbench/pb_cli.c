# include "pb_cli.h"
# include "pb_config.h"
# include "pb_worker.h"

static cli_svr *svr;

static sds on_cmd_list(const char *cmd, int argc, sds *argv)
{
    if (argc != 0) {
        sds reply = sdsempty();
        return sdscatprintf(reply, "usage: %s \"msg\"\n", cmd);
    }
    return get_worker_info();
}

int init_cli(void)
{
    svr = cli_svr_create(&settings.cli);
    if (svr == NULL) {
        return -__LINE__;
    }

    cli_svr_add_cmd(svr, "list", on_cmd_list);
    return 0;
}

