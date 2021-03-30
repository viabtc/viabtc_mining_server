/*
 * Description: 
 *     History: yang@haipo.me, 2016/06/06, create
 */

# include "bm_config.h"
# include "bm_master.h"
# include "bm_block.h"
# include "bm_tx.h"
# include "bm_request.h"
# include "ut_rpc_clt.h"

static dict_t *dict_blockmaster;
static nw_timer blockmaster_update_timer;

struct blockmaster_info {
    uint32_t id;
    rpc_clt *clt;
};

static uint32_t dict_blockmaster_hash_func(const void *key)
{
    return dict_generic_hash_function(key, strlen(key));
}

static int dict_blockmaster_key_compare(const void *key1, const void *key2)
{
    return strcmp(key1, key2);
}

static void *dict_blockmaster_key_dup(const void *key)
{
    return strdup(key);
}

static void dict_blockmaster_key_free(void *key)
{
    free(key);
}

static void *dict_blockmaster_val_dup(const void *key)
{
    struct blockmaster_info *obj = malloc(sizeof(struct blockmaster_info));
    memcpy(obj, key, sizeof(struct blockmaster_info));
    return obj;
}

static void dict_blockmaster_val_free(void *val)
{
    free(val);
}

static dict_t *create_blockmaster_dict(void)
{
    dict_types type;
    memset(&type, 0, sizeof(type));
    type.hash_function  = dict_blockmaster_hash_func;
    type.key_compare    = dict_blockmaster_key_compare;
    type.key_dup        = dict_blockmaster_key_dup;
    type.val_dup        = dict_blockmaster_val_dup;
    type.key_destructor = dict_blockmaster_key_free;
    type.val_destructor = dict_blockmaster_val_free;
    dict_t *dict = dict_create(&type, 8);

    return  dict;
}

static void on_connect(nw_ses *ses, bool result)
{
    if (result) {
        log_info("connect blockmaster: %s success", nw_sock_human_addr(&ses->peer_addr));
    } else {
        log_info("connect blockmaster: %s fail", nw_sock_human_addr(&ses->peer_addr));
    }
}

static int on_cmd_thin_block_tx(nw_ses *ses, rpc_pkg *pkg)
{
    static void *buf = NULL;
    static size_t buf_size = 32 * 1000 * 1000;
    if (buf == NULL) {
        buf = malloc(buf_size);
    }

    void *rsp_pos = buf;
    size_t rsp_left = buf_size;
    void *req_pos = pkg->body;
    size_t req_left = pkg->body_size;

    uint32_t tx_count;
    ERR_RET_LN(unpack_uint32_le(&req_pos, &req_left, &tx_count));
    log_debug("thin block tx count: %u", tx_count);
    ERR_RET_LN(pack_uint32_le(&rsp_pos, &rsp_left, tx_count));
    for (size_t i = 0; i < tx_count; ++i) {
        char key[TX_KEY_SIZE];
        ERR_RET_LN(unpack_buf(&req_pos, &req_left, key, sizeof(key)));
        sds data = get_tx_data(key);
        if (data == NULL)
            return -__LINE__;
        ERR_RET_LN(pack_varstr(&rsp_pos, &rsp_left, data, sdslen(data)));
    }

    rpc_pkg rsp;
    memcpy(&rsp, pkg, sizeof(rpc_pkg));
    rsp.pkg_type = RPC_PKG_TYPE_REPLY;
    rsp.body = buf;
    rsp.body_size = buf_size - rsp_left;
    ERR_RET_LN(rpc_send(ses, &rsp));

    return 0;
}

static void on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    int ret;
    double start = current_timestamp();

    switch (pkg->command) {
    case CMD_THIN_BLOCK_TX:
        log_info("from: %s, cmd thin block tx request", nw_sock_human_addr(&ses->peer_addr));
        ret = on_cmd_thin_block_tx(ses, pkg);
        if (ret < 0) {
            log_error("on_cmd_thin_block_tx fail: %d", ret);
        }
        break;
    default:
        log_error("unknown command: %u", pkg->command);
        return;
    };

    double end = current_timestamp();
    log_info("process command: %u time: %f", pkg->command, end - start);
}

static rpc_clt *create_blockmaster_clt(const char *node)
{
    nw_addr_t addr;
    rpc_clt_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.name = strdup("blockmaster");
    cfg.addr_count = 1;
    cfg.addr_arr = &addr;
    if (nw_sock_cfg_parse(node, &addr, &cfg.sock_type) < 0) {
        log_error("nw_sock_cfg_parse fail, node: %s", node);
        return NULL;
    }
    cfg.max_pkg_size = 8 * 1024 * 1024;
    cfg.heartbeat_timeout = settings.blockmaster_timeout;

    rpc_clt_type type;
    memset(&type, 0, sizeof(type));
    type.on_connect = on_connect;
    type.on_recv_pkg = on_recv_pkg;

    rpc_clt *clt = rpc_clt_create(&cfg, &type);
    if (clt == NULL || rpc_clt_start(clt) < 0) {
        log_error("rpc clt create fail, node: %s", node);
        return NULL;
    }

    return clt;
}

static int add_blockmaster(const char *node, uint32_t id)
{
    rpc_clt *clt = create_blockmaster_clt(node);
    if (!clt)
        return -__LINE__;

    struct blockmaster_info info = { id, clt };;
    dict_add(dict_blockmaster, (void *)node, &info);

    return 0;
}

static int del_blockmaster(const char *node)
{
    dict_entry *entry = dict_find(dict_blockmaster, node);
    if (entry) {
        struct blockmaster_info *info = entry->val;
        rpc_clt_close(info->clt);
        rpc_clt_release(info->clt);
        dict_delete(dict_blockmaster, entry->key);
    }

    return 0;
}

static int on_blockmaster_callback(json_t *reply)
{
    if (!reply || !json_is_array(reply)) {
        log_fatal("get blockmaster config reply fail");
        return -__LINE__;
    }

    char *str_new = json_dumps(reply, 0);
    char *str_old = json_dumps(settings.blockmaster_cfg, 0);
    log_info("new blockmaster config: %s, old blockmaster config: %s", str_new, str_old);

    if (strcmp(str_new, str_old) == 0) {
        free(str_new);
        free(str_old);
        return 0;
    }
    free(str_new);
    free(str_old);

    static uint32_t update_id = 0;
    update_id += 1;

    int blockmaster_count = json_array_size(reply);
    for (int i = 0; i < blockmaster_count; ++i) {
        json_t *row = json_array_get(reply, i);
        if (!json_is_string(row)) {
            log_fatal("load cfg blockmaster fail, blockmaster_cfg: %s", str_new);
            return -__LINE__;
        }

        sds node = sdsnew("tcp@");
        node = sdscat(node, json_string_value(row));

        dict_entry *entry = dict_find(dict_blockmaster, node);
        if (!entry) {
            int ret = add_blockmaster(node, update_id);
            if (ret != 0) {
                log_fatal("add blockmaster fail, ret: %d, blockmaster_cfg: %s", ret, node);
                sdsfree(node);
                return -__LINE__;
            }
            log_info("add blockmaster: %s", node);
        } else {
            struct blockmaster_info *obj = entry->val;
            obj->id = update_id;
        }
        sdsfree(node);
    }

    dict_entry *entry = NULL;
    dict_iterator *iter = dict_get_iterator(dict_blockmaster);
    while ((entry = dict_next(iter)) != NULL) {
        struct blockmaster_info *obj = entry->val;
        if (obj->id != update_id) {
            log_info("del blockmaster: %s", (char *)entry->key);
            del_blockmaster(entry->key);
        }
    }
    dict_release_iterator(iter);

    json_decref(settings.blockmaster_cfg);
    settings.blockmaster_cfg = reply;
    log_info("update blockmaster config success");

    return 0;
}

static void on_blockmaster_update(nw_timer *timer, void *privdata)
{
    update_blockmaster_config(on_blockmaster_callback);
}

int init_master(void)
{
    dict_blockmaster = create_blockmaster_dict();
    if (!dict_blockmaster)
        return -__LINE__;

    if (!settings.blockmaster_cfg || !json_is_array(settings.blockmaster_cfg))
        return -__LINE__;

    char *str = json_dumps(settings.blockmaster_cfg, 0);
    log_info("load blockmaster cfg: %s", str);
    free(str);

    int blockmaster_count = json_array_size(settings.blockmaster_cfg);
    for (int i = 0; i < blockmaster_count; ++i) {
        json_t *row = json_array_get(settings.blockmaster_cfg, i);
        if (!json_is_string(row))
            return -__LINE__;

        sds node = sdsnew("tcp@");
        node = sdscat(node, json_string_value(row));

        if (add_blockmaster(node, 0) != 0) {
            sdsfree(node);
            return -__LINE__;
        }
        sdsfree(node);
    }

    nw_timer_set(&blockmaster_update_timer, settings.blockmaster_update_interval, true, on_blockmaster_update, NULL);
    nw_timer_start(&blockmaster_update_timer);

    return 0;
}

int broadcast_master_msg(rpc_pkg *pkg)
{
    dict_entry *entry = NULL;
    dict_iterator *iter = dict_get_iterator(dict_blockmaster);
    while ((entry = dict_next(iter)) != NULL) {
        struct blockmaster_info *info = entry->val;
        if (rpc_clt_connected(info->clt)) {
            int ret = rpc_clt_send(info->clt, pkg);
            if (ret < 0) {
                log_error("send to: %s fail: %d", nw_sock_human_addr(&info->clt->raw_clt->ses.peer_addr), ret);
            }
        }
    }
    dict_release_iterator(iter);

    return 0;
}

int get_blockmaster_connection_num(void)
{
    int num = 0;
    dict_entry *entry = NULL;
    dict_iterator *iter = dict_get_iterator(dict_blockmaster);
    while ((entry = dict_next(iter)) != NULL) {
        struct blockmaster_info *info = entry->val;
        if (rpc_clt_connected(info->clt)) {
            num++;
        }
    }
    dict_release_iterator(iter);

    return num;
}

