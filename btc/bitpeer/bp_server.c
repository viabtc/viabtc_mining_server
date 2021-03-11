/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/18, create
 */

# include "bp_config.h"
# include "bp_server.h"
# include "bp_peer.h"
# include "bp_monitor.h"

static rpc_svr *svr;

static void on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    int ret;
    switch (pkg->command) {
    case CMD_SUBMIT_BLOCK:
        log_info("cmd submit block");
        ret = broadcast_block(pkg->body, pkg->body_size);
        if (ret < 0) {
            inc_submit_block_error();
            log_error("broadcast_block fail: %d", ret);
        } else {
            inc_submit_block_success();
        }
        break;
    case CMD_UPDATE_BLOCK:
        log_info("cmd update block");
        ret = broadcast_header(pkg->body, pkg->body_size);
        if (ret < 0) {
            inc_update_block_error();
            log_error("broadcast_header fail: %d", ret);
        } else {
            inc_update_block_success();
        }
        break;
    default:
        log_error("unknown command: %u", pkg->command);
        break;
    }
}

static void on_new_connection(nw_ses *ses)
{
    log_info("new connection: %s", nw_sock_human_addr(&ses->peer_addr));
}

static void on_connection_close(nw_ses *ses)
{
    log_info("connection: %s close", nw_sock_human_addr(&ses->peer_addr));
}

static int init_svr(void)
{
    rpc_svr_type type;
    memset(&type, 0, sizeof(type));
    type.on_recv_pkg = on_recv_pkg;
    type.on_new_connection = on_new_connection;
    type.on_connection_close = on_connection_close;

    svr = rpc_svr_create(&settings.svr, &type);
    if (svr == NULL)
        return -__LINE__;
    if (rpc_svr_start(svr) < 0)
        return -__LINE__;

    return 0;
}

int init_server(void)
{
    ERR_RET(init_svr());

    return 0;
}

static int broadcast_msg(rpc_pkg *pkg)
{
    nw_ses *curr = svr->raw_svr->clt_list_head;
    while (curr) {
        rpc_send(curr, pkg);
        curr = curr->next;
    }
    return 0;
}

int broadcast_block_update(void *block, size_t size)
{
    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.command = CMD_UPDATE_BLOCK;
    pkg.pkg_type = RPC_PKG_TYPE_PUSH;
    pkg.body_size = size;
    pkg.body = block;
    broadcast_msg(&pkg);
    return 0;
}

