/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/08, create
 */

# include "ut_cli.h"
# include "ma_cli.h"
# include "ma_worker.h"
# include "ma_config.h"

static cli_svr *svr;

static sds on_list_clients(const char *cmd, int argc, sds *argv)
{
    return get_clients_info();
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

    return 0;
}

