/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/08, create
 */

# include "ut_cli.h"
# include "gw_cli.h"
# include "gw_worker.h"
# include "gw_config.h"

static cli_svr *svr;

static sds on_list_clients(const char *cmd, int argc, sds *argv)
{
    return get_clients_info();
}

static sds on_set_coin_name(const char *cmd, int argc, sds *argv)
{
    if (argc != 1) {
        sds reply = sdsempty();
        return sdscatprintf(reply, "usage: %s name\n", cmd);
    }

    free(settings.coin);
    settings.coin = strdup(argv[0]);
    return sdsnew("ok\n");
}

static sds on_get_coin_name(const char *cmd, int argc, sds *argv)
{
    sds reply = sdsempty();
    return sdscatprintf(reply, "%s\n", settings.coin);
}

static sds on_flush_workers(const char *cmd, int argc, sds *argv)
{
    flush_worker_info();
    return sdsnew("ok\n");
} 

int init_cli(int id)
{
    if (settings.cli.addr.family == AF_INET) {
        settings.cli.addr.in.sin_port = htons(ntohs(settings.cli.addr.in.sin_port) + id);
    } else if (settings.cli.addr.family == AF_INET6) {
        settings.cli.addr.in6.sin6_port = htons(ntohs(settings.cli.addr.in6.sin6_port) + id);
    }

    svr = cli_svr_create(&settings.cli);
    if (svr == NULL) {
        return -__LINE__;
    }

    cli_svr_add_cmd(svr, "list", on_list_clients);
    cli_svr_add_cmd(svr, "setcoinname", on_set_coin_name);
    cli_svr_add_cmd(svr, "getcoinname", on_get_coin_name);
    cli_svr_add_cmd(svr, "flushworker", on_flush_workers);

    return 0;
}

