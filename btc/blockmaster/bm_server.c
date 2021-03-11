/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/18, create
 */

# include "bm_config.h"
# include "bm_server.h"
# include "bm_block.h"
# include "bm_tx.h"
# include "nw_state.h"
# include "bm_monitor.h"

static rpc_svr *svr;
static nw_state *state;

static void on_state_timeout(nw_state_entry *entry)
{
    log_error("state entry: %u timeout", entry->id);
}

static void on_state_release(nw_state_entry *entry)
{
    free(((rpc_pkg *)entry->data)->body);
}

static int on_cmd_submit_block(rpc_pkg *pkg)
{
    static char hash_last[32];
    char hash[32];
    sha256d(pkg->body, pkg->body_size, hash);
    if (memcmp(hash, hash_last, 32) == 0)
        return 0;
    memcpy(hash_last, hash, 32);

    int ret = on_submit_block(pkg->body, pkg->body_size);
    if (ret < 0) {
        log_error("on_submit_block fail: %d", ret);
        return -__LINE__;
    }

    return 0;
}

static int send_thin_block_tx_req(nw_ses *ses, rpc_pkg *pkg, uint32_t count, sds info)
{
    char buf[1000 * 1000];
    void *p = buf;
    size_t left = sizeof(buf);

    ERR_RET_LN(pack_uint32_le(&p, &left, count));
    ERR_RET_LN(pack_buf(&p, &left, info, sdslen(info)));

    nw_state_entry *entry = nw_state_add(state, 10.0, 0);
    if (entry == NULL)
        return -__LINE__;
    rpc_pkg *state_data = entry->data;
    memcpy(state_data, pkg, sizeof(rpc_pkg));
    state_data->body = malloc(state_data->body_size);
    memcpy(state_data->body, pkg->body, state_data->body_size);

    rpc_pkg req;
    memset(&req, 0, sizeof(req));
    req.command = CMD_THIN_BLOCK_TX;
    req.sequence = entry->id;
    req.pkg_type = RPC_PKG_TYPE_REQUEST;
    req.body = buf;
    req.body_size = sizeof(buf) - left;

    log_info("unknown tx count: %u, send tx request sequence: %u", count, entry->id);
    return rpc_send(ses, &req);
}

static int on_cmd_thin_block(nw_ses *ses, rpc_pkg *pkg)
{
    void *p = pkg->body;
    size_t left = pkg->body_size;

    char block_hash[32];
    ERR_RET_LN(unpack_buf(&p, &left, block_hash, sizeof(block_hash)));
    if (is_block_exist(block_hash)) {
        return 0;
    }

    char block_head[80];
    ERR_RET_LN(unpack_buf(&p, &left, block_head, sizeof(block_head)));
    sds block = sdsempty();
    block = sdscatlen(block, block_head, sizeof(block_head));

    sds coinbase_tx;
    uint32_t tx_count;
    ERR_RET_LN(unpack_varstr(&p, &left, &coinbase_tx));
    ERR_RET_LN(unpack_uint32_le(&p, &left, &tx_count));
    log_debug("thin block tx count: %u", tx_count);

    char tmp[10];
    void *tmp_ptr = tmp;
    size_t tmp_left = sizeof(tmp);
    pack_varint_le(&tmp_ptr, &tmp_left, tx_count + 1);
    block = sdscatlen(block, tmp, sizeof(tmp) - tmp_left);
    block = sdscatlen(block, coinbase_tx, sdslen(coinbase_tx));
    sdsfree(coinbase_tx);

    uint32_t unknown_tx_count = 0;
    sds unknown_tx_info = sdsempty();
    for (uint32_t i = 0; i < tx_count; ++i) {
        char key[TX_KEY_SIZE];
        ERR_RET_LN(unpack_buf(&p, &left, key, sizeof(key)));
        sds data = get_tx_data(key);
        if (!data) {
            unknown_tx_count += 1;
            unknown_tx_info = sdscatlen(unknown_tx_info, key, sizeof(key));
        } else {
            block = sdscatlen(block, data, sdslen(data));
        }
    }

    if (unknown_tx_count == 0) {
        log_info("get full block from thin");
        if (pkg->command == CMD_THIN_BLOCK_SUBMIT) {
            int ret = on_submit_block(block, sdslen(block));
            if (ret < 0) {
                log_error("on_submit_block fail: %d", ret);
            }
        } else {
            int ret = on_update_block(block, sdslen(block));
            if (ret < 0) {
                log_error("on_update_block fail: %d", ret);
            }
        }
    } else {
        if (ses) {
            int ret = send_thin_block_tx_req(ses, pkg, unknown_tx_count, unknown_tx_info);
            if (ret < 0) {
                log_error("send_thin_block_tx_req fail: %d", ret);
            }
        } else {
            log_error("unkown tx count: %u", unknown_tx_count);
        }
    }

    sdsfree(block);
    sdsfree(unknown_tx_info);

    return 0;
}

static int on_cmd_thin_tx(nw_ses *ses, rpc_pkg *pkg)
{
    nw_state_entry *entry = nw_state_get(state, pkg->sequence);
    if (entry == NULL) {
        log_error("get state entry: %u fail", pkg->sequence);
        return -__LINE__;
    }

    void *p = pkg->body;
    size_t left = pkg->body_size;

    uint32_t tx_count;
    ERR_RET_LN(unpack_uint32_le(&p, &left, &tx_count));
    log_debug("thin tx data count: %u", tx_count);
    for (uint32_t i = 0; i < tx_count; ++i) {
        sds data;
        char tx_hash[32];
        ERR_RET_LN(unpack_varstr(&p, &left, &data));
        sha256d(data, sdslen(data), tx_hash);
        reverse_mem(tx_hash, sizeof(tx_hash));
        update_tx(tx_hash, data, sdslen(data));
        sdsfree(data);
    }

    int ret = on_cmd_thin_block(NULL, entry->data);
    if (ret < 0) {
        log_error("on_cmd_thin_block fail: %d", ret);
    }

    nw_state_del(state, pkg->sequence);
    return 0;
}

static void on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    int ret;
    double start = current_timestamp();

    switch (pkg->command) {
    case CMD_SUBMIT_BLOCK:
        log_info("from: %s, cmd submit block", nw_sock_human_addr(&ses->peer_addr));
        ret = on_cmd_submit_block(pkg);
        if (ret < 0) {
            inc_submit_block_error();
            log_error("on_cmd_submit_block fail: %d", ret);
        } else {
            inc_submit_block_success();
        }
        break;
    case CMD_THIN_BLOCK_SUBMIT:
    case CMD_THIN_BLOCK_UPDATE:
        log_info("from: %s, cmd thin block: %u", nw_sock_human_addr(&ses->peer_addr), pkg->command);
        ret = on_cmd_thin_block(ses, pkg);
        if (ret < 0) {
            inc_thin_block_submit_update_error(pkg->command);
            log_error("on_cmd_thin_block fail: %d", ret);
        } else {
            inc_thin_block_submit_update_success(pkg->command);
        }
        break;
    case CMD_THIN_BLOCK_TX:
        log_info("from: %s, cmd thin block tx reply", nw_sock_human_addr(&ses->peer_addr));
        ret = on_cmd_thin_tx(ses, pkg);
        if (ret < 0) {
            inc_thin_block_tx_error();
            log_error("on_cmd_thin_tx fail: %d", ret);
        } else {
            inc_thin_block_tx_success();
        }
        break;
    default:
        log_error("unknown command: %u", pkg->command);
        return;
    }

    double end = current_timestamp();
    log_info("process command: %u time: %f", pkg->command, end - start);
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

    struct nw_state_type state_type;
    state_type.on_timeout = on_state_timeout;
    state_type.on_release = on_state_release;

    state = nw_state_create(&state_type, sizeof(struct rpc_pkg));
    if (state == NULL)
        return -__LINE__;

    return 0;
}

int init_server(void)
{
    ERR_RET(init_svr());

    return 0;
}

