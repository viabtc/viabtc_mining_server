/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/08, create
 */

# include "ut_cli.h"
# include "mw_config.h"
# include "mw_cli.h"
# include "mw_receiver.h"

static cli_svr *svr;

static sds on_load_trust(const char *cmd, int argc, sds *argv)
{
    if (argc != 1) {
        sds reply = sdsempty();
        return sdscatprintf(reply, "usage: %s filename\n", cmd);
    }
    sds filename = argv[0];
    int ret = load_trust(filename);
    if (ret < 0) {
        sds reply = sdsempty();
        return sdscatprintf(reply, "%s failed: %d\n", cmd, ret);
    }
    return sdsnew("ok\n");
}

static sds on_list_trust(const char *cmd, int argc, sds *argv)
{
    return list_trust();
}

int init_cli()
{
    svr = cli_svr_create(&settings.cli);
    if (svr == NULL) {
        return -__LINE__;
    }

    cli_svr_add_cmd(svr, "listtrust", on_list_trust);
    cli_svr_add_cmd(svr, "loadtrust", on_load_trust);

    return 0;
}
