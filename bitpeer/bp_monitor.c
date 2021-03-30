# include "bp_config.h"
# include "bp_monitor.h"
# include "bp_peer.h"

static http_svr *svr;

static uint32_t submit_block_success_num;
static uint32_t submit_block_error_num;
static uint32_t update_block_success_num;
static uint32_t update_block_error_num;
static dict_t   *dict_p2p_count;

struct cmd_p2p_info {
    uint32_t success_num;
    uint32_t error_num; 
};

static uint32_t dict_p2p_hash_func(const void *key)
{
    return dict_generic_hash_function(key, strlen(key));
}

static int dict_p2p_key_compare(const void *key1, const void *key2)
{
    return strcmp(key1, key2);
}

static void *dict_p2p_key_dup(const void *key)
{
    return strdup(key);
}

static void dict_p2p_key_free(void *key)
{
    free(key);
}

static void *dict_p2p_val_dup(const void *key)
{
    struct cmd_p2p_info *obj = malloc(sizeof(struct cmd_p2p_info));
    memcpy(obj, key, sizeof(struct cmd_p2p_info));
    return obj;
}

static void dict_p2p_val_free(void *val)
{
    free(val);
}

static void reply_data(nw_ses *ses, int64_t id, int code, const char *message, json_t *data)
{
    json_t *error = json_object();
    json_object_set_new(error, "code", json_integer(code));
    json_object_set_new(error, "message", json_string(message));
    json_t *reply = json_object();
    json_object_set_new(reply, "error", error);
    if (data)
        json_object_set(reply, "result", data);
    else
        json_object_set_new(reply, "result", json_null());
    json_object_set_new(reply, "id", json_integer(id));

    char *reply_str = json_dumps(reply, 0);
    send_http_response_simple(ses, 200, reply_str, strlen(reply_str));
    free(reply_str);
    json_decref(reply);
}

static void reset_bitpeer_info(void)
{
    dict_clear(dict_p2p_count);
    submit_block_success_num = 0;
    submit_block_error_num = 0;
    update_block_success_num = 0;
    update_block_error_num = 0;
}

static int handle_get_bitpeer_info(nw_ses *ses, int64_t id, json_t *params)
{
    json_t *connection_info_obj = json_object();
    json_object_set_new(connection_info_obj, "peer_limit", json_integer(get_peer_limit()));
    json_object_set_new(connection_info_obj, "peer_num", json_integer(get_peer_num()));

    json_t *cmd_submit_block_obj = json_object();
    json_object_set_new(cmd_submit_block_obj, "success", json_integer(submit_block_success_num));
    json_object_set_new(cmd_submit_block_obj, "error", json_integer(submit_block_error_num));

    json_t *cmd_update_block_obj = json_object();
    json_object_set_new(cmd_update_block_obj, "success", json_integer(update_block_success_num));
    json_object_set_new(cmd_update_block_obj, "error", json_integer(update_block_error_num));

    json_t *result = json_object();
    dict_entry *entry = NULL;
    dict_iterator *iter = dict_get_iterator(dict_p2p_count);
    while ((entry = dict_next(iter)) != NULL) {
        struct cmd_p2p_info *info = entry->val;
        char cmd_p2p_str[30];
        snprintf(cmd_p2p_str, sizeof(cmd_p2p_str), "cmd_p2p_%s", (char *)entry->key);

        json_t *p2p_meta_obj = json_object();
        json_object_set_new(p2p_meta_obj, "success", json_integer(info->success_num));
        json_object_set_new(p2p_meta_obj, "error", json_integer(info->error_num));
        json_object_set_new(result, cmd_p2p_str, p2p_meta_obj);
    }
    dict_release_iterator(iter);

    json_object_set_new(result, "bitpeer_peer_connection", connection_info_obj);
    json_object_set_new(result, "bitpeer_cmd_submit_block", cmd_submit_block_obj);
    json_object_set_new(result, "bitpeer_cmd_update_block", cmd_update_block_obj);

    reply_data(ses, id, 0, "ok", result);
    json_decref(result);
    reset_bitpeer_info();

    return 0;
}

static int on_http_request(nw_ses *ses, http_request_t *request)
{
    log_trace("new http request, url: %s, method: %u", request->url, request->method);
    if (request->method == HTTP_GET) {
        return send_http_response_simple(ses, 200, "ok\n", 3);
    } else {
        if (request->method != HTTP_POST || !request->body) {
            log_error("connection: %"PRIu64":%s, empty body", ses->id, nw_sock_human_addr(&ses->peer_addr));
            send_http_response_simple(ses, 400, NULL, 0);
            return -__LINE__;
        }
    }

    json_t *body = json_loadb(request->body, sdslen(request->body), 0, NULL);
    if (body == NULL) {
        goto decode_error;
    }
    json_t *id = json_object_get(body, "id");
    if (!id || !json_is_integer(id)) {
        goto decode_error;
    }
    json_t *method = json_object_get(body, "method");
    if (!method || !json_is_string(method)) {
        goto decode_error;
    }
    json_t *params = json_object_get(body, "params");
    if (!params || !json_is_array(params)) {
        goto decode_error;
    }
    log_trace("from: %s body: %s", nw_sock_human_addr(&ses->peer_addr), request->body);

    const char *_method = json_string_value(method);
    if (strcmp(_method, "get_bitpeer_info") == 0) {
        int ret = handle_get_bitpeer_info(ses, json_integer_value(id), params);
        if (ret < 0) {;
            log_error("connection: %"PRIu64":%s, error_interval_error: %d", ses->id, nw_sock_human_addr(&ses->peer_addr), ret);
            send_http_response_simple(ses, 500, NULL, 0);
        }
    } else {
        log_error("connection: %"PRIu64":%s, unknown method: %s, request: %s", ses->id,
                nw_sock_human_addr(&ses->peer_addr), _method, request->body);
        send_http_response_simple(ses, 404, NULL, 0);
    }

    json_decref(body);
    return 0;

decode_error:
    if (body)
        json_decref(body);
    sds hex = hexdump(request->body, sdslen(request->body));
    log_error("peer: %s, decode request fail, request body: \n%s", nw_sock_human_addr(&ses->peer_addr), hex);
    sdsfree(hex);
    send_http_response_simple(ses, 400, NULL, 0);
    return -__LINE__;
}

int init_monitor_server(void)
{
    dict_types type;
    memset(&type, 0, sizeof(type));
    type.hash_function  = dict_p2p_hash_func;
    type.key_compare    = dict_p2p_key_compare;
    type.key_dup        = dict_p2p_key_dup;
    type.val_dup        = dict_p2p_val_dup;
    type.key_destructor = dict_p2p_key_free;
    type.val_destructor = dict_p2p_val_free;

    dict_p2p_count = dict_create(&type, 8);
    if (!dict_p2p_count)
        return -__LINE__;

    nw_svr_bind *bind_arr = settings.http_svr.bind_arr;
    if (bind_arr->addr.family == AF_INET) {
        bind_arr->addr.in.sin_port = htons(ntohs(bind_arr->addr.in.sin_port));
    } else if (bind_arr->addr.family == AF_INET6) {
        bind_arr->addr.in6.sin6_port = htons(ntohs(bind_arr->addr.in6.sin6_port));
    }

    svr = http_svr_create(&settings.http_svr, on_http_request);
    if (svr == NULL)
        return -__LINE__;

    ERR_RET(http_svr_start(svr));

    return 0;
}

void inc_p2p_success(const char *cmd)
{
    dict_entry *entry = dict_find(dict_p2p_count, cmd);
    if (entry == NULL) {
        struct cmd_p2p_info info;
        memset(&info, 0, sizeof(info));
        info.success_num = 1;
        dict_add(dict_p2p_count, (void *)cmd, &info);
        return;
    }

    struct cmd_p2p_info *obj = entry->val;
    ++obj->success_num;
}

void inc_p2p_error(const char *cmd)
{
    dict_entry *entry = dict_find(dict_p2p_count, cmd);
    if (entry == NULL) {
        struct cmd_p2p_info info;
        memset(&info, 0, sizeof(info));
        info.error_num = 1;
        dict_add(dict_p2p_count, (void *)cmd, &info);
        return;
    }

    struct cmd_p2p_info *obj = entry->val;
    ++obj->error_num;
}

void inc_submit_block_success(void)
{
    submit_block_success_num++;
}

void inc_submit_block_error(void)
{
    submit_block_error_num++;
}

void inc_update_block_success(void)
{
    update_block_success_num++;
}

void inc_update_block_error(void)
{
    update_block_error_num++;
}


