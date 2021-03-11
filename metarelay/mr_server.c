/*
 * Description: 
 *     History: yang@haipo.me, 2016/12/07, create
 */

# include "mr_config.h"
# include "mr_server.h"
# include "mr_writer.h"
# include "mr_writer2.h"

static rpc_svr *svr;
static nw_svr *monitor_svr;

static void svr_on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    log_debug("request from: %"PRIu64":%s sequence: %u", ses->id, nw_sock_human_addr(&ses->peer_addr), pkg->sequence);
    int ret = push_message(pkg);
    if (ret < 0) {
        log_error("push_message fail: %d", ret);
    }

    if (settings.spilt) {
        ret = push_message2(pkg);
        if (ret < 0) {
            log_error("push_message2 fail: %d", ret);
        }
    }

    rpc_pkg rsp;
    memcpy(&rsp, pkg, sizeof(rpc_pkg));
    rsp.pkg_type    = RPC_PKG_TYPE_REPLY;
    rsp.result      = 0;
    rsp.body_size   = 0;
    rsp.body        = NULL;
    rpc_send(ses, &rsp);
}

static void svr_on_new_connection(nw_ses *ses)
{
    log_info("new connection from: %"PRIu64":%s", ses->id, nw_sock_human_addr(&ses->peer_addr));
    bool trust = false;
    const char *remote_ip = nw_sock_ip(&ses->peer_addr);
    for (int i = 0; i < settings.trust_count; ++i) {
        if (strcmp(remote_ip, settings.trust_list[i]) == 0) {
            trust = true;
        }
    }
    if (!trust) {
        log_info("peer: %s not trust", nw_sock_human_addr(&ses->peer_addr));
        rpc_svr_close_clt(svr, ses);
    }
}

static void svr_on_connection_close(nw_ses *ses)
{
    log_info("connection: %"PRIu64":%s close", ses->id, nw_sock_human_addr(&ses->peer_addr));
}

static int init_svr(void)
{
    rpc_svr_type type;
    memset(&type, 0, sizeof(type));
    type.on_recv_pkg = svr_on_recv_pkg;
    type.on_new_connection = svr_on_new_connection;
    type.on_connection_close = svr_on_connection_close;

    svr = rpc_svr_create(&settings.svr, &type);
    if (svr == NULL)
        return -__LINE__;
    if (rpc_svr_start(svr) < 0)
        return -__LINE__;

    return 0;
}

static int monitor_decode_pkg(nw_ses *ses, void *data, size_t max)
{
    return max;
}
static void monitor_on_recv_pkg(nw_ses *ses, void *data, size_t size)
{
    return;
}

static int init_monitor_svr(void)
{
    nw_svr_type type;
    memset(&type, 0, sizeof(type));
    type.decode_pkg = monitor_decode_pkg;
    type.on_recv_pkg = monitor_on_recv_pkg;

    monitor_svr = nw_svr_create(&settings.monitor, &type, NULL);
    if (monitor_svr == NULL)
        return -__LINE__;
    if (nw_svr_start(monitor_svr) < 0)
        return -__LINE__;

    return 0;
}

int init_server(void)
{
    ERR_RET(init_svr());
    ERR_RET(init_monitor_svr());

    return 0;
}

