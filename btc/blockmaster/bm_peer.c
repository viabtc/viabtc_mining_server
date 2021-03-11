/*
 * Description: 
 *     History: yang@haipo.me, 2016/06/06, create
 */

# include "bm_config.h"
# include "bm_peer.h"
# include "bm_block.h"
# include "ut_rpc_clt.h"

static int clt_count;
static rpc_clt **clt_arr;

static void on_connect(nw_ses *ses, bool result)
{
    if (result) {
        log_info("connect peer: %s success", nw_sock_human_addr(&ses->peer_addr));
    } else {
        log_info("connect peer: %s fail", nw_sock_human_addr(&ses->peer_addr));
    }
}

static int on_cmd_update_block(rpc_pkg *pkg)
{
    static char hash_last[32];
    char hash[32];
    sha256d(pkg->body, pkg->body_size, hash);
    if (memcmp(hash, hash_last, 32) == 0)
        return 0;
    memcpy(hash_last, hash, 32);

    int ret = on_update_block(pkg->body, pkg->body_size);
    if (ret < 0)
        return ret;

    return 0;
}

static void on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    int ret;
    double start = current_timestamp();

    switch (pkg->command) {
    case CMD_UPDATE_BLOCK:
        log_info("from: %s, cmd update block", nw_sock_human_addr(&ses->peer_addr));
        ret = on_cmd_update_block(pkg);
        if (ret < 0) {
            log_error("on_cmd_update_block fail: %d", ret);
        }
        break;
    default:
        log_error("unknown command: %u", pkg->command);
        break;
    };

    double end = current_timestamp();
    log_info("process command: %u time: %f", pkg->command, end - start);
}

int init_peer(void)
{
    clt_count = settings.bitpeer_count;
    clt_arr = malloc(sizeof(void *) * clt_count);
    for (int i = 0; i < clt_count; ++i) {
        nw_addr_t addr;
        rpc_clt_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = strdup("peer");
        cfg.addr_count = 1;
        cfg.addr_arr = &addr;
        if (nw_sock_cfg_parse(settings.bitpeers[i], &addr, &cfg.sock_type) < 0)
            return -__LINE__;
        cfg.max_pkg_size = 8 * 1024 * 1024;
        cfg.heartbeat_timeout = settings.bitpeer_timeout;

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

int broadcast_peer_msg(rpc_pkg *pkg)
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

