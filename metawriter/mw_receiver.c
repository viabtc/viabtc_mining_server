/*
 * Description: 
 *     History: yang@haipo.me, 2016/12/04, create
 */

# include "mw_config.h"
# include "mw_receiver.h"
# include "ut_dict.h"

static rpc_svr *svr;
static rpc_clt *clt;
static nw_svr *monitor_svr;
static dict_t *trust_dict;

# define MAX_IP_LEN 15
# define MAX_INFO_LEN 50

static void svr_on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    log_info("cmd:%d, body_size:%d", pkg->command, pkg->body_size);
    log_trace("request from: %"PRIu64":%s sequence: %u", ses->id, nw_sock_human_addr(&ses->peer_addr), pkg->sequence);
    int ret = rpc_clt_send(clt, pkg);
    if(ret < 0){
        log_error("rpc_clt_send error: %d", ret);
        return;
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
    const char *remote_ip = nw_sock_ip(&ses->peer_addr);
    sds key = sdsnew(remote_ip);
    dict_entry *entry = dict_find(trust_dict, key);
    sdsfree(key);
    if (!entry) {
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

static void clt_on_connect(nw_ses *ses, bool result)
{
    if (result) {
        log_info("connect worker: %s success", nw_sock_human_addr(&ses->peer_addr));
    } else {
        log_info("connect worker: %s fail", nw_sock_human_addr(&ses->peer_addr));
    }
}

static void clt_on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    return;
}

static int init_clt(void)
{
    rpc_clt_cfg cfg;
    nw_addr_t addr;
    memset(&cfg, 0, sizeof(cfg));
    cfg.name = strdup("worker");
    cfg.addr_count = 1;
    cfg.addr_arr = &addr;
    if (nw_sock_cfg_parse(MW_WORKER_BIND, &addr, &cfg.sock_type) < 0)
        return -__LINE__;
    cfg.max_pkg_size = settings.svr.max_pkg_size;
    cfg.heartbeat_timeout = 3600;

    rpc_clt_type type;
    memset(&type, 0, sizeof(type));
    type.on_connect = clt_on_connect;
    type.on_recv_pkg = clt_on_recv_pkg;

    clt = rpc_clt_create(&cfg, &type);
    if (clt == NULL)
        return -__LINE__;
    if (rpc_clt_start(clt) < 0)
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

static uint32_t trust_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sdslen((sds)key));
}

static int trust_dict_key_compare(const void *key1, const void *key2)
{
    return sdscmp((sds)key1, (sds)key2);
}

static void trust_dict_key_free(void *key)
{
    sdsfree((sds)key);
}

static void trust_dict_val_free(void *val)
{
    sdsfree((sds)val);
}

static int init_dict(void)
{
    dict_types type;
    memset(&type, 0, sizeof(type));
    type.hash_function = trust_dict_hash_func;
    type.key_compare = trust_dict_key_compare;
    type.key_destructor = trust_dict_key_free;
    type.val_destructor = trust_dict_val_free;

    trust_dict = dict_create(&type, 1024);
    if (trust_dict == NULL)
        return -__LINE__;

    return 0;
}

sds list_trust()
{
    sds s = sdsempty();
    s = sdscatprintf(s, "%-15s %-50s\n", "ip", "info");

    dict_iterator *iter = dict_get_iterator(trust_dict);
    dict_entry *entry;
    while ((entry = dict_next(iter)) != NULL) {
        sds ip = entry->key;
        sds info = entry->val;
        s = sdscatprintf(s, "%-15s %-50s\n", ip, info);
    }
    dict_release_iterator(iter);

    return s;
}

int load_trust(const char *filename)
{
    json_error_t error;
    double start = current_timestamp();
    json_t *trust_object = json_load_file(filename, 0, &error);
    if (trust_object == NULL) {
        log_error("json_load_file from: %s fail: %s in line: %d", filename, error.text, error.line);
        return -__LINE__;
    }
    
    if (!json_is_object(trust_object)) {
        json_decref(trust_object);
        return -__LINE__;
    }

    dict_clear(trust_dict);
    const char *key;
    json_t *val;
    json_object_foreach(trust_object, key, val) {
        if (strlen(key) >0 && strlen(key) <= MAX_IP_LEN && json_is_string(val) && strlen(json_string_value(val)) > 0 && strlen(json_string_value(val)) <= MAX_INFO_LEN) {
            sds info = sdsnew(json_string_value(val));
            log_trace("reload trust ip: %s, info: %s", key, info);
            sds ip = sdsnew(key);
            dict_add(trust_dict, ip, info);
        }
    }    
    json_decref(trust_object);

    double end = current_timestamp();
    log_info("load trust file cost time: %f, trust count: %d", end - start, trust_dict->used);
    return 0;
}

int init_receiver(void)
{
    ERR_RET(init_dict());
    ERR_RET(load_trust(settings.trust_file));
    ERR_RET(init_svr());
    ERR_RET(init_clt());
    ERR_RET(init_monitor_svr());

    return 0;
}

