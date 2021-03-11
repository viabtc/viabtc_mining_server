# include "jm_config.h"
# include "jm_monitor.h"
# include "jm_job.h"

static http_svr *svr;
static rpc_clt *jobmonitor_clt;
static double ttl;

static uint32_t submit_main_success_num;
static uint32_t submit_main_error_num;
static uint32_t submit_aux_success_num;
static uint32_t submit_aux_error_num;
static uint32_t spv_total_num;
static uint32_t spv_timeout_num;
static uint32_t recv_out_height_num;

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

static void reset_jobmaster_info(void)
{
    submit_main_success_num = 0;
    submit_main_error_num = 0;
    submit_aux_success_num = 0;
    submit_aux_error_num = 0;
    spv_total_num = 0;
    spv_timeout_num = 0;
    recv_out_height_num = 0;
}

static int handle_get_jobmaster_info(nw_ses *ses, int64_t id, json_t *params)
{
    json_t *submit_main_obj = json_object();
    json_object_set_new(submit_main_obj, "success", json_integer(submit_main_success_num));
    json_object_set_new(submit_main_obj, "error", json_integer(submit_main_error_num));

    json_t *submit_aux_info = json_object();
    json_object_set_new(submit_aux_info, "success", json_integer(submit_aux_success_num));
    json_object_set_new(submit_aux_info, "error", json_integer(submit_aux_error_num));

    json_t *spv_obj = json_object();
    json_object_set_new(spv_obj, "total", json_integer(spv_total_num));
    json_object_set_new(spv_obj, "error", json_integer(spv_timeout_num));

    json_t *recv_out_height_obj = json_object();
    json_object_set_new(recv_out_height_obj, "count", json_integer(recv_out_height_num));

    json_t *result = json_object();
    json_object_set_new(result, "jobmaster_submit_main", submit_main_obj);
    json_object_set_new(result, "jobmaster_submit_aux", submit_aux_info);
    json_object_set_new(result, "jobmaster_spv", spv_obj);
    json_object_set_new(result, "jobmaster_recv_out_height", recv_out_height_obj);

    reply_data(ses, id, 0, "ok", result);
    json_decref(result);
    reset_jobmaster_info();

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
    if (strcmp(_method, "get_jobmaster_info") == 0) {
        int ret = handle_get_jobmaster_info(ses, json_integer_value(id), params);
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

static int send_jobmaster_register(nw_ses *ses)
{
    json_t *params = json_object();
    json_object_set_new(params, "timestamp", json_real(current_timestamp()));
    json_object_set_new(params, "host", json_string(settings.alert.host));
    json_object_set_new(params, "coinname", json_string(settings.main_coin.name));

    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.pkg_type  = RPC_PKG_TYPE_REQUEST;
    pkg.command   = CMD_JOBMONITOR_REGISTER;
    pkg.body      = json_dumps(params, 0);
    pkg.body_size = strlen(pkg.body);

    rpc_clt_send(jobmonitor_clt, &pkg);
    log_trace("send request to %s, cmd: %u, sequence: %u, params: %s",
            nw_sock_human_addr(rpc_clt_peer_addr(jobmonitor_clt)), pkg.command, pkg.sequence, (char *)pkg.body);
    free(pkg.body);
    json_decref(params);
    return 0;
}

int send_jobmaster_update(uint32_t height)
{
    json_t *params = json_object();
    json_object_set_new(params, "timestamp", json_real(current_timestamp()));
    json_object_set_new(params, "ttl", json_real(ttl));
    json_object_set_new(params, "height", json_integer(height));
    json_object_set_new(params, "coinname", json_string(settings.main_coin.name));

    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.pkg_type  = RPC_PKG_TYPE_REQUEST;
    pkg.command   = CMD_JOBMONITOR_UPDATE;
    pkg.body      = json_dumps(params, 0);
    pkg.body_size = strlen(pkg.body);

    rpc_clt_send(jobmonitor_clt, &pkg);
    log_trace("send request to %s, cmd: %u, sequence: %u, params: %s",
            nw_sock_human_addr(rpc_clt_peer_addr(jobmonitor_clt)), pkg.command, pkg.sequence, (char *)pkg.body);
    free(pkg.body);
    json_decref(params);
    return 0;
}

static void on_connect(nw_ses *ses, bool result)
{
    if (result) {
        send_jobmaster_register(ses);
        log_info("connect jobmonitor: %s success", nw_sock_human_addr(&ses->peer_addr));
    } else {
        log_info("connect jobmonitor: %s fail", nw_sock_human_addr(&ses->peer_addr));
    }
}

static void on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    sds data = sdsnewlen(pkg->body, pkg->body_size);
    log_info("from: %s recv jobmonitor message: %s", nw_sock_human_addr(&ses->peer_addr), data);
    json_t *message = json_loadb(data, sdslen(data), 0, NULL);
    if (message == NULL) {
        log_error("decode message fail, peer: %s message: %s", nw_sock_human_addr(&ses->peer_addr), data);
        sdsfree(data);
        return;
    }
    sdsfree(data);

    if (json_is_null(json_object_get(message, "error"))) {
        json_t *timestamp = json_object_get(message, "result");
        if (timestamp != NULL && json_is_real(timestamp)) {
            ttl = (current_timestamp() - json_real_value(timestamp)) / 2;
            log_info("from: %s ttl: %lf", nw_sock_human_addr(&ses->peer_addr), ttl);
        }

        if (pkg->command == CMD_JOBMONITOR_REGISTER) {
            send_jobmaster_update(get_current_height());
        }
    }

    json_decref(message);
    return;
}

static int init_jobmonitor(void)
{
    nw_addr_t addr;
    rpc_clt_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.name = strdup("jobmonitor");
    cfg.addr_count = 1;
    cfg.addr_arr = &addr;
    if (nw_sock_cfg_parse(settings.jobmonitor, &addr, &cfg.sock_type) < 0)
        return -__LINE__;
    cfg.max_pkg_size = 8 * 1024 * 1024;
    cfg.heartbeat_timeout = 60;

    rpc_clt_type type;
    memset(&type, 0, sizeof(type));
    type.on_connect = on_connect;
    type.on_recv_pkg = on_recv_pkg;

    jobmonitor_clt = rpc_clt_create(&cfg, &type);
    if (jobmonitor_clt == NULL)
        return -__LINE__;
    if (rpc_clt_start(jobmonitor_clt) < 0)
        return -__LINE__;

    return 0;
}

int init_monitor(void)
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
    ERR_RET(init_jobmonitor());

    return 0;
}

void inc_submit_main_success(void)
{
    submit_main_success_num++;
}

void inc_submit_main_error(void)
{
    submit_main_error_num++;
}

void inc_submit_aux_success(void)
{
    submit_aux_success_num++;
}

void inc_submit_aux_error(void)
{
    submit_aux_error_num++;
}

void inc_spv_total(void)
{
    spv_total_num++;
}

void inc_spv_timeout(void)
{
    spv_timeout_num++;
}

void inc_recv_out_height(void)
{
    recv_out_height_num++;
}


