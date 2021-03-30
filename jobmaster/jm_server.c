/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/03, create
 */

# include "jm_config.h"
# include "jm_server.h"
# include "jm_job.h"
# include "jm_monitor.h"

static rpc_svr *svr;
static rpc_clt *brother;
static dict_t *ban_dict;
static nw_timer ban_timer;

struct ban_info {
    time_t ban_start;
    time_t ban_limit;
};

static int process_cmd_found_block(nw_ses *ses, rpc_pkg *pkg)
{
    sds data = sdsnewlen(pkg->body, pkg->body_size);
    log_info("from: %s recv found block message: %s", nw_sock_human_addr(&ses->peer_addr), data);
    json_t *message = json_loadb(data, sdslen(data), 0, NULL);
    if (message == NULL) {
        log_error("decode message fail, peer: %s message: %s", nw_sock_human_addr(&ses->peer_addr), data);
        sdsfree(data);
        return -__LINE__;
    }
    sdsfree(data);

    sds job_id = sdsnew(json_string_value(json_object_get(message, "job_id")));
    sds block_head = sdsnew(json_string_value(json_object_get(message, "block_head")));
    sds coinbase = sdsnew(json_string_value(json_object_get(message, "coinbase")));
    const char *type = json_string_value(json_object_get(message, "type"));
    const char *name = json_string_value(json_object_get(message, "name"));

    if (strcmp(type, "main") == 0) {
        int ret = on_found_block_main(job_id, block_head, coinbase);
        if (ret < 0) {
            log_fatal("on_found_block_main fail: %d", ret);
        }
    } else {
        int ret = on_found_block_aux(job_id, block_head, coinbase, name);
        if (ret < 0) {
            log_fatal("on_found_block_aux fail: %d", ret);
        }
    }

    sdsfree(job_id);
    sdsfree(block_head);
    sdsfree(coinbase);
    json_decref(message);

    return 0;
}

static void add_ban_ip(const char *ip, int limit)
{
    sds key = sdsnew(ip);
    dict_entry *entry = dict_find(ban_dict, key);
    if (entry) {
        struct ban_info *info = entry->val;
        info->ban_limit = limit;
        log_info("update ban ip: %s, limit: %d", ip, limit);
        sdsfree(key);
        return;
    }

    struct ban_info *info = malloc(sizeof(struct ban_info));
    info->ban_start = time(NULL);
    info->ban_limit = limit;
    dict_add(ban_dict, key, info);
    log_info("add ban ip: %s, limit: %d", ip, limit);
}

static void del_ban_ip(const char *ip)
{
    sds key = sdsnew(ip);
    dict_delete(ban_dict, key);
    sdsfree(key);
    log_info("del ban ip: %s", ip);
}

int process_cmd_update_ban(nw_ses *ses, rpc_pkg *pkg)
{
    json_t *message = json_loadb(pkg->body, pkg->body_size, 0, NULL);
    if (message == NULL) {
        sds hex = hexdump(pkg->body, pkg->body_size);
        log_error("decode message fail, msg: \n%s", hex);
        sdsfree(hex);
        return -__LINE__;
    }

    json_t *ip_obj = json_object_get(message, "ip");
    json_t *op_obj = json_object_get(message, "op");
    if (ip_obj == NULL || op_obj == NULL) {
        json_decref(message);
        return -__LINE__;
    }

    if (strcmp(json_string_value(op_obj), "add") == 0) {
        json_t *limit_obj = json_object_get(message, "limit");
        if (limit_obj == NULL) {
            json_decref(message);
            return -__LINE__;
        }
        size_t index;
        json_t *value;
        json_array_foreach(ip_obj, index, value) {
            add_ban_ip(json_string_value(value), json_integer_value(limit_obj));
        }
    } else if (strcmp(json_string_value(op_obj), "del") == 0) {
        size_t index;
        json_t *value;
        json_array_foreach(ip_obj, index, value) {
            del_ban_ip(json_string_value(value));
        }
    }

    json_decref(message);
    broadcast_msg(pkg);

    return 0;
}

static int process_cmd_height_update(nw_ses *ses, rpc_pkg *pkg)
{
    json_t *message = json_loadb(pkg->body, pkg->body_size, 0, NULL);
    if (message == NULL) {
        sds hex = hexdump(pkg->body, pkg->body_size);
        log_error("decode message fail, msg: \n%s", hex);
        sdsfree(hex);
        return -__LINE__;
    }

    int height = 0;
    uint32_t curtime = 0;
    uint32_t nbits = 0;
    const char *target = NULL;
    const char *prevhash = NULL;

    json_t *height_obj = json_object_get(message, "height");
    if (height_obj && json_is_integer(height_obj)) {
        height = json_integer_value(height_obj);
    } else {
        json_decref(message);
        return -__LINE__;
    }

    json_t *curtime_obj = json_object_get(message, "curtime");
    if (curtime_obj && json_is_integer(curtime_obj)) {
        curtime = json_integer_value(curtime_obj);
    } else {
        json_decref(message);
        return -__LINE__;
    }

    json_t *nbits_obj = json_object_get(message, "nbits");
    if (nbits_obj && json_is_integer(nbits_obj)) {
        nbits = json_integer_value(nbits_obj);
    }

    json_t *target_obj = json_object_get(message, "target");
    if (target_obj && json_is_string(target_obj)) {
        sds bin = hex2bin(json_string_value(target_obj));
        if (!bin || sdslen(bin) != 32) {
            json_decref(message);
            return -__LINE__;
        }
        sdsfree(bin);
        target = json_string_value(target_obj);
    }

    json_t *prevhash_obj = json_object_get(message, "prevhash");
    if (prevhash_obj && json_is_string(prevhash_obj)) {
        sds bin = hex2bin(json_string_value(prevhash_obj));
        if (!bin || sdslen(bin) != 32) {
            json_decref(message);
            return -__LINE__;
        }
        sdsfree(bin);
        prevhash = json_string_value(prevhash_obj);
    } else {
        json_decref(message);
        return -__LINE__;
    }

    inc_recv_out_height();
    int ret = on_height_update(height, curtime, nbits, target, prevhash);
    if (ret < 0) {
        log_error("on_height_update fail: %d, height: %d, curtime: %u, nbits: %u, target: %s, prevhash: %s",
                ret, height, curtime, nbits, target, prevhash);
        json_decref(message);
        return -__LINE__;
    }

    json_decref(message);
    return 0;
}

static void svr_on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    int ret;
    switch (pkg->command) {
    case CMD_FOUND_BLOCK:
        log_debug("from: %s found block", nw_sock_human_addr(&ses->peer_addr));
        ret = process_cmd_found_block(ses, pkg);
        if (ret < 0) {
            log_fatal("process_cmd_found_block fail: %d", ret);
        }
        break;
    case CMD_UPDATE_BAN:
        log_debug("from: %s update ban", nw_sock_human_addr(&ses->peer_addr));
        ret = process_cmd_update_ban(ses, pkg);
        if (ret < 0) {
            log_error("process_cmd_update_ban fail: %d", ret);
        }
        break;
    case CMD_HEIGHT_UPDATE:
        log_debug("from: %s height update", nw_sock_human_addr(&ses->peer_addr));
        ret = process_cmd_height_update(ses, pkg);
        if (ret < 0) {
            log_fatal("process_cmd_height_update fail: %d", ret);
        }
        break;
    default:
        log_error("unknown command: %u", pkg->command);
        break;
    }
}

static void send_banned_ip(nw_ses *ses)
{
    json_t *ip_list = json_array();
    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(ban_dict);
    while ((entry = dict_next(iter)) != NULL) {
        json_array_append_new(ip_list, json_string(entry->key));
    }
    dict_release_iterator(iter);

    json_t *message = json_object();
    json_object_set_new(message, "ip", ip_list);
    json_object_set_new(message, "op", json_string("add"));

    char *message_data = json_dumps(message, 0);
    if (message_data == NULL) {
        json_decref(message);
        return;
    }
    json_decref(message);

    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.command = CMD_UPDATE_BAN;
    pkg.pkg_type = RPC_PKG_TYPE_REQUEST;
    pkg.body_size = strlen(message_data);
    pkg.body = message_data;

    rpc_send(ses, &pkg);
    free(message_data);
}

static void svr_on_new_connection(nw_ses *ses)
{
    log_info("new connection: %s", nw_sock_human_addr(&ses->peer_addr));
    int ret = send_curr_job(ses);
    if (ret < 0) {
        log_error("send curr job fail: %d, close connection", ret);
        rpc_svr_close_clt(svr, ses);
        return;
    }
    send_banned_ip(ses);
}

static void svr_on_connection_close(nw_ses *ses)
{
    log_info("connection: %s close", nw_sock_human_addr(&ses->peer_addr));
}

static void brother_on_connect(nw_ses *ses, bool result)
{
    if (result) {
        log_info("connect brother: %s success", nw_sock_human_addr(&ses->peer_addr));
    } else {
        log_info("connect brother: %s fail", nw_sock_human_addr(&ses->peer_addr));
    }
}

static void brother_on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    switch (pkg->command) {
    case CMD_UPDATE_BAN:
        if (pkg->pkg_type != RPC_PKG_TYPE_REQUEST)
            break;
        pkg->pkg_type = RPC_PKG_TYPE_PUSH;
        broadcast_msg(pkg);
        break;
    default:
        break;
    }
}

static uint32_t ban_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sdslen((sds)key));
}
static int ban_dict_key_compare(const void *key1, const void *key2)
{
    return sdscmp((sds)key1, (sds)key2);
}
static void ban_dict_key_free(void *key)
{
    sdsfree((sds)key);
}
static void ban_dict_val_free(void *val)
{
    free(val);
}

static void ban_on_timer(nw_timer *timer, void *privdata)
{
    time_t now = time(NULL);
    json_t *ip_list = json_array();
    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(ban_dict);
    while ((entry = dict_next(iter)) != NULL) {
        struct ban_info *info = entry->val;
        if (info->ban_limit && now - info->ban_start > info->ban_limit) {
            json_array_append_new(ip_list, json_string(entry->key));
        }
    }
    dict_release_iterator(iter);
    broadcast_del_ban_ip(ip_list);
    json_decref(ip_list);
}

int init_svr(void)
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

int init_brother(void)
{
    if (!settings.has_brother) {
        return 0;
    }

    rpc_clt_type type;
    memset(&type, 0, sizeof(type));
    type.on_connect = brother_on_connect;
    type.on_recv_pkg = brother_on_recv_pkg;

    brother = rpc_clt_create(&settings.brother, &type);
    if (brother == NULL)
        return -__LINE__;
    if (rpc_clt_start(brother) < 0)
        return -__LINE__;

    return 0;
}

int init_dict(void)
{
    dict_types type_ban;
    memset(&type_ban, 0, sizeof(type_ban));
    type_ban.hash_function  = ban_dict_hash_func;
    type_ban.key_compare    = ban_dict_key_compare;
    type_ban.key_destructor = ban_dict_key_free;
    type_ban.val_destructor = ban_dict_val_free;
    ban_dict = dict_create(&type_ban, 64);
    if (ban_dict == NULL)
        return -__LINE__;

    return 0;
}

int init_server(void)
{
    ERR_RET(init_svr());
    ERR_RET(init_brother());
    ERR_RET(init_dict());

    nw_timer_set(&ban_timer, 60.0, true, ban_on_timer, NULL);
    nw_timer_start(&ban_timer);

    return 0;
}

int close_all_connection(void)
{
    nw_ses *curr = svr->raw_svr->clt_list_head;
    while (curr) {
        nw_ses *next = curr->next;
        nw_svr_close_clt(svr->raw_svr, curr);
        curr = next;
    }

    return 0;
}

int broadcast_msg(rpc_pkg *pkg)
{
    nw_ses *curr = svr->raw_svr->clt_list_head;
    while (curr) {
        rpc_send(curr, pkg);
        curr = curr->next;
    }
    return 0;
}

static int broadcast_ban(json_t *message)
{
    char *message_data = json_dumps(message, 0);
    if (message_data == NULL) {
        return -__LINE__;
    }

    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.command = CMD_UPDATE_BAN;
    pkg.pkg_type = RPC_PKG_TYPE_REQUEST;
    pkg.body_size = strlen(message_data);
    pkg.body = message_data;

    broadcast_msg(&pkg);
    free(message_data);

    return 0;
}

int broadcast_add_ban_ip(json_t *ip_list, int limit)
{
    size_t index;
    json_t *value;
    json_array_foreach(ip_list, index, value) {
        add_ban_ip(json_string_value(value), limit);
    }

    json_t *message = json_object();
    json_object_set_new(message, "ip", ip_list);
    json_object_set_new(message, "op", json_string("add"));
    json_object_set_new(message, "limit", json_integer(limit));

    broadcast_ban(message);
    json_decref(message);

    return 0;
}

int broadcast_del_ban_ip(json_t *ip_list)
{
    size_t index;
    json_t *value;
    json_array_foreach(ip_list, index, value) {
        del_ban_ip(json_string_value(value));
    }

    json_t *message = json_object();
    json_object_set(message, "ip", ip_list);
    json_object_set_new(message, "op", json_string("del"));

    broadcast_ban(message);
    json_decref(message);

    return 0;
}

sds get_ban_ip_list(void)
{
    sds s = sdsempty();
    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(ban_dict);
    while ((entry = dict_next(iter)) != NULL) {
        struct ban_info *info = entry->val;
        s = sdscatprintf(s, "%s ~ ", strftimestamp(info->ban_start));
        s = sdscatprintf(s, "%s ", info->ban_limit == 0 ? "                   " : strftimestamp(info->ban_start + info->ban_limit));
        s = sdscatprintf(s, "%s\n", (sds)entry->key);
    }
    dict_release_iterator(iter);
    return s;
}

