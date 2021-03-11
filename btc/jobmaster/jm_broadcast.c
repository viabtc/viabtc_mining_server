/*
 * Description: 
 *     History: yang@haipo.me, 2016/06/06, create
 */

# include "jm_config.h"
# include "jm_broadcast.h"
# include "ut_rpc_clt.h"

static int clt_count;
static rpc_clt **clt_arr;

static void on_connect(nw_ses *ses, bool result)
{
    if (result) {
        log_info("connect blockmaster: %s success", nw_sock_human_addr(&ses->peer_addr));
    } else {
        log_info("connect blockmaster: %s fail", nw_sock_human_addr(&ses->peer_addr));
    }
}

static void on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    return;
}

int init_broadcast(void)
{
    clt_count = settings.blockmaster_count;
    clt_arr = malloc(sizeof(void *) * clt_count);
    for (int i = 0; i < clt_count; ++i) {
        nw_addr_t addr;
        rpc_clt_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = strdup("blockmaster");
        cfg.addr_count = 1;
        cfg.addr_arr = &addr;
        if (nw_sock_cfg_parse(settings.blockmasters[i], &addr, &cfg.sock_type) < 0)
            return -__LINE__;
        cfg.max_pkg_size = 8 * 1024 * 1024;
        cfg.heartbeat_timeout = settings.blockmaster_timeout;

        rpc_clt_type type;
        memset(&type, 0, sizeof(type));
        type.on_connect = on_connect;
        type.on_recv_pkg = on_recv_pkg;

        clt_arr[i] = rpc_clt_create(&cfg, &type);
        if (clt_arr[i] == NULL)
            return -__LINE__;
        if (rpc_clt_start(clt_arr[i]) < 0)
            return -__LINE__;
    }

    return 0;
}

int broadcast_block_msg(rpc_pkg *pkg)
{
    for (int i = 0; i < clt_count; ++i) {
        if (rpc_clt_connected(clt_arr[i])) {
            int ret = rpc_clt_send(clt_arr[i], pkg);
            if (ret < 0) {
                log_error("send to: %s fail: %d", nw_sock_human_addr(&clt_arr[i]->raw_clt->ses.peer_addr), ret);
            }
        }
    }

    return 0;
}

