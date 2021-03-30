/*
 * Description: 
 *     History: yang@haipo.me, 2016/06/22, create
 */

# include <netdb.h>

# include "pb_config.h"
# include "pb_worker.h"
# include "ut_pack.h"
# include "pb_request.h"

static int worker_count;
static nw_clt **worker_list;
static nw_timer timer;
static nw_timer jobmaster_update_timer;
static double best_height_timestamp;
static int best_height;
static int sockfd;

struct worker_info {
    char    *name;
    char    *host;
    int     port;
    char    *user;
    char    *pass;
    bool    auth;
    bool    is_notify;
    bool    is_self;
    int     height;
    double  timestamp;
    time_t  last_active;
    bool    last_clean_empty;
    double  last_clean_time;
};

static char *get_sock_cfg(const char *host, int port)
{
    static char str[128];
    char ip[INET6_ADDRSTRLEN];
    struct hostent *hp = gethostbyname(host);
    if (hp == NULL) {
        return NULL;
    }
    if (hp->h_length == 0) {
        return NULL;
    }
    inet_ntop(hp->h_addrtype, hp->h_addr_list[0], ip, sizeof(ip));
    snprintf(str, sizeof(str), "tcp@%s:%u", ip, port);
    return str;
}

static int decode_pkg(nw_ses *ses, void *data, size_t max)
{
    log_info("on_connect");
    char *s = data;
    for (size_t i = 0; i < max; ++i) {
        if (s[i] == '\n')
            return i + 1;
    }
    return 0;
}

static int on_close(nw_ses *ses)
{
    struct worker_info *info = ses->privdata;
    info->auth = false;
    info->height = 0;

    log_error("pool: %s, addr: %s close", info->name, nw_sock_human_addr(&ses->peer_addr));
    char *sock_cfg = get_sock_cfg(info->host, info->port);
    if (sock_cfg == NULL) {
        log_error("get_sock_cfg, host: %s", info->host);
        return 0;
    }
    if (nw_sock_cfg_parse(sock_cfg, &ses->peer_addr, &ses->sock_type) < 0) {
        log_error("nw_sock_cfg_parse: %s fail", sock_cfg);
        return 0;
    }

    return 0;
}

static int send_json(nw_ses *ses, json_t *message)
{
    char *message_data = json_dumps(message, 0);
    if (message_data == NULL)
        return -__LINE__;
    log_trace("connection: %"PRIu64":%s send: %s", ses->id, nw_sock_human_addr(&ses->peer_addr), message_data);

    size_t message_size = strlen(message_data);
    message_data[message_size++] = '\n';
    nw_ses_send(ses, message_data, message_size);
    free(message_data);

    return 0;
}

static int send_subscribe(nw_ses *ses)
{
    json_t *message = json_object();
    json_object_set_new(message, "id", json_integer(current_timestamp() * 1000));
    json_object_set_new(message, "method", json_string("mining.subscribe"));

    json_t *params = json_array();
    json_object_set_new(message, "params", params);

    send_json(ses, message);
    json_decref(message);

    return 0;
}

static int send_auth(struct worker_info *info, nw_ses *ses)
{
    json_t *message = json_object();
    json_object_set_new(message, "id", json_integer(current_timestamp() * 1000));
    json_object_set_new(message, "method", json_string("mining.authorize"));

    json_t *params = json_array();
    json_array_append_new(params, json_string(info->user));
    json_array_append_new(params, json_string(info->pass));
    json_object_set_new(message, "params", params);

    send_json(ses, message);
    json_decref(message);

    return 0;
}

static void on_connect(nw_ses *ses, bool result)
{
    struct worker_info *info = ses->privdata;
    log_info("on_connect");
    if (result) {
        log_info("connect pool: %s, addr: %s success", info->name, nw_sock_human_addr(&ses->peer_addr));
        send_subscribe(ses);
    } else {
        log_error("connect pool: %s, addr: %s fail", info->name, nw_sock_human_addr(&ses->peer_addr));
    }
}

static int send_block_nitify(sds hash, int height, uint32_t curtime)
{
    json_t *message = json_object();
    json_object_set_new(message, "height", json_integer(height));
    json_object_set_new(message, "curtime", json_integer(curtime));
    json_object_set_new(message, "prevhash", json_string(hash));

    char *message_data = json_dumps(message, 0);
    if (message_data == NULL) {
        log_error("json_dumps fail");
        json_decref(message);
        return -__LINE__;
    }
    json_decref(message);
    log_debug("block notify msg: %s", message_data);

    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.command = CMD_HEIGHT_UPDATE;
    pkg.pkg_type = RPC_PKG_TYPE_PUSH;
    pkg.body_size = strlen(message_data);
    pkg.body = message_data;

    void *pkg_data;
    uint32_t pkg_size;
    int ret = rpc_pack(&pkg, &pkg_data, &pkg_size);
    if (ret < 0) {
        log_error("rpc_pack fail: %d", ret);
        free(message_data);
        return -__LINE__;
    }
    free(message_data);

    for (size_t i = 0; i < settings.jobmaster->count; ++i) {
        struct sockaddr_in *addr = &settings.jobmaster->arr[i];
        sendto(sockfd, pkg_data, pkg_size, 0, (struct sockaddr *)addr, sizeof(*addr));
    }

    return 0;
}

int handle_mining_notify(struct worker_info *info, json_t *request)
{
    json_t *params = json_object_get(request, "params");
    if (params == NULL || !json_is_array(params))
        return -__LINE__;
    json_t *coinb1 = json_array_get(params, 2);
    if (coinb1 == NULL || !json_is_string(coinb1))
        return -__LINE__;
    sds coinb1_bin = hex2bin(json_string_value(coinb1));
    if (coinb1_bin == NULL)
        return -__LINE__;
    if (sdslen(coinb1_bin) < 42) {
        sdsfree(coinb1_bin);
        return -__LINE__;
    }

    void *p = coinb1_bin + 42;
    size_t left = sdslen(coinb1_bin) - 42;
    int64_t height = 0;
    if (unpack_oppushint_le(&p, &left, &height) < 0) {
        sdsfree(coinb1_bin);
        return -__LINE__;
    }
    sdsfree(coinb1_bin);

    double now_ms = current_timestamp();
    if (info->height != height) {
        if (info->is_self && best_height > 0 && info->height > 0) {
            double time_delay = now_ms - best_height_timestamp;
            if (best_height > height - 1) {
                log_fatal("pool: %s delayed, height: %"PRIu64", best_height: %d", info->name, height - 1, best_height);
            } else if (best_height == height - 1 && time_delay > settings.max_delay) {
                log_fatal("pool: %s delayed: %lf, height: %"PRIu64", best_height: %d", info->name, time_delay, height - 1, best_height);
            }
        }
        info->height = height;
        info->timestamp = now_ms;
        log_info("pool: %s update height to: %"PRIu64"", info->name, height);
    }

    if (json_is_true(json_array_get(params, 8))) {
        if (json_array_size(json_array_get(params, 4)) == 0) {
            info->last_clean_empty = true;
            info->last_clean_time = current_timestamp();
        }
    } else if (info->last_clean_empty) {
        if (json_array_size(json_array_get(params, 4)) > 0) {
            log_info("pool: %s height: %d spv mining time: %f",
                    info->name, info->height, current_timestamp() - info->last_clean_time);
            info->last_clean_empty = false;
        }
    }

    if (settings.is_notify && info->is_notify && best_height < (height - 1)) {
        json_t *prevhash = json_array_get(params, 1);
        if (!prevhash || !json_is_string(prevhash))
            return -__LINE__;
        json_t *curtime = json_array_get(params, 7);
        if (!curtime || !json_is_string(curtime))
            return -__LINE__;
        sds prevhash_bin = hex2bin(json_string_value(prevhash));
        if(prevhash_bin == NULL)
            return -__LINE__;
        if (sdslen(prevhash_bin) != 32) {
            sdsfree(prevhash_bin);
            return -__LINE__;
        }

        for (int i = 0; i < 8; ++i) {
            reverse_mem(prevhash_bin + i * 4, 4);
        }
        reverse_mem(prevhash_bin, 32);
        sds prevhash_hex = bin2hex(prevhash_bin, 32);
        sdsfree(prevhash_bin);
        uint32_t curtime_val = strtoul(json_string_value(curtime), NULL, 16);
        uint32_t now = time(NULL);
        if (curtime_val < now) {
            curtime_val = now;
        }
        log_info("notify: height: %d, hash: %s, time: %u", (int)height - 1, prevhash_hex, curtime_val);
        int ret = send_block_nitify(prevhash_hex, height - 1, curtime_val);
        if (ret < 0) {
            log_error("send_block_nitify fail: %d", ret);
            sdsfree(prevhash_hex);
            return -__LINE__;
        }

        sdsfree(prevhash_hex);
        best_height = height - 1;
        best_height_timestamp = now_ms;
    }

    return 0;
}

static void on_recv_pkg(nw_ses *ses, void *data, size_t size)
{
    struct worker_info *info = ses->privdata;
    info->last_active = time(NULL);
    json_t *request = json_loadb(data, size - 1, 0, NULL);
    if (request == NULL) {
        goto decode_error;
    }

    char *request_data = data;
    request_data[size - 1] = '\0';
    log_trace("pool: %s, addr: %s, recv: %s", info->name, nw_sock_human_addr(&ses->peer_addr), request_data);

    json_t *result = json_object_get(request, "result");
    if (result) {
        if (json_is_array(result)) {
            if (!info->auth) {
                send_auth(info, ses);
            }
        } else if (json_is_true(result)) {
            log_info("pool: %s authorized", info->name);
            info->auth = true;
        }
    } else {
        json_t *method = json_object_get(request, "method");
        if (method != NULL && strcmp(json_string_value(method), "mining.notify") == 0) {
            int ret = handle_mining_notify(info, request);
            if (ret < 0) {
                log_error("handle_mining_notify fail: %d, request: %s", ret, request_data);
            }
        }
    }

    json_decref(request);
    return;

decode_error:
    if (request) {
        json_decref(request);
    }
    sds hex = hexdump(data, size - 1);
    log_error("pool: %s, addr: %s decode request fail, request data: \n%s", info->name, nw_sock_human_addr(&ses->peer_addr), hex);
    sdsfree(hex);
}

static void on_error_msg(nw_ses *ses, const char *msg)
{
    struct worker_info *info = ses->privdata;
    log_error("pool: %s, addr: %s, error: %s", info->name, nw_sock_human_addr(&ses->peer_addr), msg);
}

static void on_timer(nw_timer *timer, void *privdata)
{
    time_t now = time(NULL);
    for (int i = 0; i < worker_count; ++i) {
        nw_ses *ses = &worker_list[i]->ses;
        struct worker_info *info = ses->privdata;
        if (info->is_self && best_height > 0) {
            double now_ms = current_timestamp();
            double time_delay = now_ms - best_height_timestamp;
            if (info->height > 0 && info->height - 1 < best_height && time_delay > settings.max_delay) {
                log_fatal("pool: %s delayed: %lf, height: %d, best_height: %d", info->name, time_delay, info->height - 1, best_height);
            }
        }
        if (now - info->last_active > 600) {
            log_error("pool: %s, addr: %s, not active too long", info->name, nw_sock_human_addr(&ses->peer_addr));
            nw_clt_close(worker_list[i]);
            info->auth = false;
            info->height = 0;
            nw_clt_start(worker_list[i]);
        }
    }
}

sds get_worker_info()
{
    sds s = sdsempty();
    s = sdscatprintf(s, "%-35s %-10s %-20s %-10s\n", "name", "is_self", "timestamp", "height");
    for (int i = 0; i < worker_count; ++i) {
        nw_ses *ses = &worker_list[i]->ses;
        struct worker_info *info = ses->privdata;
        s = sdscatprintf(s, "%-35s %-10s %-10.10f %-10d\n", info->name, info->is_self ? "Yes" : "No", info->timestamp, info->height);
    }
    s = sdscatprintf(s, "best_height: %d, timestamp: %lf\n", best_height, best_height_timestamp);
    return s;
}

static void inetv4_list_free(inetv4_list *list)
{
    if (list) {
        if (list->arr)
            free(list->arr);
        free(list);
    }
}

static int on_jobmaster_callback(json_t *reply)
{
    if (!reply) {
        log_fatal("get jobmaster config null");
        return -__LINE__;
    }

    char *str_new = json_dumps(reply, 0);
    char *str_old = json_dumps(settings.jobmaster_cfg, 0);
    log_info("new jobmaster config: %s, old jobmaster config: %s", str_new, str_old);

    inetv4_list *jobmaster = malloc(sizeof(inetv4_list));
    int ret = load_cfg_inetv4_list_direct(reply, jobmaster);
    if (ret < 0) {
        log_fatal("update jobmaster fail, ret: %d, json reply: %s", ret, str_new);
        free(str_new);
        free(str_old);
        inetv4_list_free(jobmaster);
        return -__LINE__;
    }
    free(str_new);
    free(str_old);

    json_decref(settings.jobmaster_cfg);
    settings.jobmaster_cfg = reply;

    inetv4_list_free(settings.jobmaster);
    settings.jobmaster = jobmaster;
    log_info("update jobmaster config success");

    return 0;
}

static void on_jobmaster_update(nw_timer *timer, void *privdata)
{
    update_jobmaster_config(on_jobmaster_callback);
}

int init_worker(void)
{
    worker_count = settings.pool_count;
    worker_list = malloc(sizeof(void *) * worker_count);
    for (int i = 0; i < worker_count; ++i) {
        nw_clt_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        char *sock_cfg = get_sock_cfg(settings.pool_list[i].host, settings.pool_list[i].port);
        if (sock_cfg == NULL) {
            printf("get_sock_cfg fail, host: %s\n", settings.pool_list[i].host);
            return -__LINE__;
        }
        if (nw_sock_cfg_parse(sock_cfg, &cfg.addr, &cfg.sock_type) < 0) {
            printf("nw_sock_cfg_parse: %s fail\n", sock_cfg);
            return -__LINE__;
        }
        cfg.max_pkg_size = 10240;
        cfg.reconnect_timeout = 0.1;

        nw_clt_type type;
        memset(&type, 0, sizeof(type));
        type.decode_pkg = decode_pkg;
        type.on_close = on_close;
        type.on_connect = on_connect;
        type.on_recv_pkg = on_recv_pkg;
        type.on_error_msg = on_error_msg;

        struct worker_info *info = malloc(sizeof(struct worker_info));
        memset(info, 0, sizeof(struct worker_info));
        info->name = strdup(settings.pool_list[i].name);
        info->host = strdup(settings.pool_list[i].host);
        info->port = settings.pool_list[i].port;
        info->user = strdup(settings.pool_list[i].user);
        info->pass = strdup(settings.pool_list[i].pass);
        info->is_notify = settings.pool_list[i].is_notify;
        info->is_self   = settings.pool_list[i].is_self;
        info->last_active = time(NULL);

        worker_list[i] = nw_clt_create(&cfg, &type, info);
        if (worker_list[i] == NULL) {
            printf("create worker: %s fail\n", info->name);
            return -__LINE__;
        }
        if (nw_clt_start(worker_list[i]) < 0) {
            return -__LINE__;
        }
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -__LINE__;

    nw_timer_set(&timer, 0.1, true, on_timer, NULL);
    nw_timer_start(&timer);

    nw_timer_set(&jobmaster_update_timer, settings.jobmaster_update_interval, true, on_jobmaster_update, NULL);
    nw_timer_start(&jobmaster_update_timer);

    return 0;
}

