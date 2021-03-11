# include "gw_config.h"
# include "gw_worker.h"

static http_svr *svr;

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


static int handle_getclientsinfo(nw_ses *ses, int64_t id, json_t *params)
{
    json_t *clients_info = get_clients_info_json();
    if (clients_info) {
        reply_data(ses, id, 0, "ok", clients_info);
        json_decref(clients_info);
    } else {
        reply_data(ses, id, 1, "empty info", NULL);
    }
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
    if (strcmp(_method, "getclientsinfo") == 0) {
        int ret = handle_getclientsinfo(ses, json_integer_value(id), params);
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

int init_http_server(int id)
{
    nw_svr_bind *bind_arr = settings.http_svr.bind_arr;
    if (bind_arr->addr.family == AF_INET) {
        bind_arr->addr.in.sin_port = htons(ntohs(bind_arr->addr.in.sin_port) + id);
    } else if (bind_arr->addr.family == AF_INET6) {
        bind_arr->addr.in6.sin6_port = htons(ntohs(bind_arr->addr.in6.sin6_port) + id);
    }

    svr = http_svr_create(&settings.http_svr, on_http_request);
    if (svr == NULL)
        return -__LINE__;

    ERR_RET(http_svr_start(svr));

    return 0;
}