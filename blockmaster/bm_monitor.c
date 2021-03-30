# include "bm_config.h"
# include "bm_monitor.h"
# include "bm_master.h"
# include "bm_block.h"

static http_svr *svr;

static uint32_t submit_block_success_num;
static uint32_t submit_block_error_num;
static uint32_t thin_block_submit_success_num;
static uint32_t thin_block_submit_error_num;
static uint32_t thin_block_update_success_num;
static uint32_t thin_block_update_error_num;
static uint32_t thin_block_tx_success_num;
static uint32_t thin_block_tx_error_num;

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

static void reset_blockmaster_info(void)
{
    submit_block_success_num = 0;
    submit_block_error_num = 0;
    thin_block_submit_success_num = 0;
    thin_block_submit_error_num = 0;
    thin_block_update_success_num = 0;
    thin_block_update_error_num = 0;
    thin_block_tx_success_num = 0;
    thin_block_tx_error_num = 0;
}

static int handle_get_blockmaster_info(nw_ses *ses, int64_t id, json_t *params)
{
    json_t *blockmaster_connection_obj = json_object();
    json_object_set_new(blockmaster_connection_obj, "conf_num", json_integer(json_array_size(settings.blockmaster_cfg)));
    json_object_set_new(blockmaster_connection_obj, "real_num", json_integer(get_blockmaster_connection_num()));

    json_t *cmd_submit_block_obj = json_object();
    json_object_set_new(cmd_submit_block_obj, "success", json_integer(submit_block_success_num));
    json_object_set_new(cmd_submit_block_obj, "error", json_integer(submit_block_error_num));

    json_t *cmd_thin_block_submit_obj = json_object();
    json_object_set_new(cmd_thin_block_submit_obj, "success", json_integer(thin_block_submit_success_num));
    json_object_set_new(cmd_thin_block_submit_obj, "error", json_integer(thin_block_submit_error_num));

    json_t *cmd_thin_block_update_obj = json_object();
    json_object_set_new(cmd_thin_block_update_obj, "success", json_integer(thin_block_update_success_num));
    json_object_set_new(cmd_thin_block_update_obj, "error", json_integer(thin_block_update_error_num));

    json_t *cmd_cmd_thin_block_tx_obj = json_object();
    json_object_set_new(cmd_cmd_thin_block_tx_obj, "success", json_integer(thin_block_tx_success_num));
    json_object_set_new(cmd_cmd_thin_block_tx_obj, "error", json_integer(thin_block_tx_error_num));

    json_t *height_info_obj = json_object();
    json_object_set_new(height_info_obj, "outer_height", json_integer(get_outer_height()));
    json_object_set_new(height_info_obj, "self_height", json_integer(get_self_height()));

    json_t *result = json_object();
    json_object_set_new(result, "blockmaster_connection", blockmaster_connection_obj);
    json_object_set_new(result, "blockmaster_cmd_submit_block", cmd_submit_block_obj);
    json_object_set_new(result, "blockmaster_cmd_thin_block_submit", cmd_thin_block_submit_obj);
    json_object_set_new(result, "blockmaster_cmd_thin_block_update", cmd_thin_block_update_obj);
    json_object_set_new(result, "blockmaster_cmd_thin_block_tx", cmd_cmd_thin_block_tx_obj);
    json_object_set_new(result, "blockmaster_height_info", height_info_obj);

    reply_data(ses, id, 0, "ok", result);
    json_decref(result);
    reset_blockmaster_info();

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
    if (strcmp(_method, "get_blockmaster_info") == 0) {
        int ret = handle_get_blockmaster_info(ses, json_integer_value(id), params);
        if (ret < 0) {
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

void inc_submit_block_success(void)
{
    submit_block_success_num++;
}

void inc_submit_block_error(void)
{
    submit_block_error_num++;
}

void inc_thin_block_submit_update_success(uint32_t cmd)
{
    if (cmd == CMD_THIN_BLOCK_SUBMIT) {
        thin_block_submit_success_num++;
    } else if (cmd == CMD_THIN_BLOCK_UPDATE) {
        thin_block_update_success_num++;
    }
}

void inc_thin_block_submit_update_error(uint32_t cmd)
{
    if (cmd == CMD_THIN_BLOCK_SUBMIT) {
        thin_block_submit_error_num++;
    } else if (cmd == CMD_THIN_BLOCK_UPDATE) {
        thin_block_update_error_num++;
    }
}

void inc_thin_block_tx_success(void)
{
    thin_block_tx_success_num++;
}

void inc_thin_block_tx_error(void)
{
    thin_block_tx_error_num++;
}

