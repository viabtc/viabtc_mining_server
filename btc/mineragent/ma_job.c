/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/04, create
 */

# include <netdb.h>

# include "ma_job.h"
# include "ma_worker.h"
# include "ma_config.h"
# include "ut_pack.h"

static nw_clt *clt;
static dict_t *job_dict;
static struct job *curr_job;
static uint16_t curr_job_id;
static json_t *curr_job_message;
static double diff1_bignum;
static nw_timer timer;
static bool agent_status;
static time_t last_activity;
static time_t last_real_job;
static time_t last_connected;
static time_t last_broadcast;

static void job_free(struct job *job)
{
    if (job->prevhash_hex)
        sdsfree(job->prevhash_hex);
    if (job->pool_name)
        sdsfree(job->pool_name);
    if (job->coinbase_message)
        sdsfree(job->coinbase_message);
    if (job->coinbaseaux_bin)
        sdsfree(job->coinbaseaux_bin);
    if (job->coinbase1_bin)
        sdsfree(job->coinbase1_bin);
    if (job->coinbase2_bin)
        sdsfree(job->coinbase2_bin);
    if (job->coinbase2_hex)
        sdsfree(job->coinbase2_hex);
    if (job->merkle_branch) {
        for (size_t i = 0; i < job->merkle_branch_count; ++i)
            sdsfree(job->merkle_branch[i]);
        free(job->merkle_branch);
    }
    if (job->merkle_json)
        json_decref(job->merkle_json);
    if (job->name)
        sdsfree(job->name);
    if (job->aux_hash)
        sdsfree(job->aux_hash);
    if (job->aux_name)
        sdsfree(job->aux_name);
    free(job);
}

static int decode_job(json_t *message, struct job *job)
{
    json_t *job_id_obj = json_object_get(message, "job_id");
    if (!job_id_obj || !json_is_string(job_id_obj))
        return -__LINE__;
    snprintf(job->job_id, sizeof(job->job_id), "%s", json_string_value(job_id_obj));
    job->job_id_num = strtoul(job->job_id, NULL, 16);

    json_t *version_obj = json_object_get(message, "version");
    if (!version_obj || !json_is_integer(version_obj))
        return -__LINE__;
    job->version = json_integer_value(version_obj);
    sprintf(job->version_hex, "%08x", job->version);

    json_t *curtime_obj = json_object_get(message, "curtime");
    if (!curtime_obj || !json_is_integer(curtime_obj))
        return -__LINE__;
    job->curtime = json_integer_value(curtime_obj);
    sprintf(job->curtime_hex, "%08x", job->curtime);

    json_t *nbits_obj = json_object_get(message, "nbits");
    if (!nbits_obj || !json_is_integer(nbits_obj))
        return -__LINE__;
    job->nbits = json_integer_value(nbits_obj);
    sprintf(job->nbits_hex, "%08x", job->nbits);

    json_t *height_obj = json_object_get(message, "height");
    if (!height_obj || !json_is_integer(height_obj))
        return -__LINE__;
    job->height = json_integer_value(height_obj);

    json_t *prevhash_obj = json_object_get(message, "prevhash");
    if (!prevhash_obj || !json_is_string(prevhash_obj))
        return -__LINE__;
    sds prevhash_bin = hex2bin(json_string_value(prevhash_obj));
    if (!prevhash_bin || sdslen(prevhash_bin) != sizeof(job->prevhash)) {
        sdsfree(prevhash_bin);
        return -__LINE__;
    }
    memcpy(job->prevhash, prevhash_bin, sizeof(job->prevhash));
    sdsfree(prevhash_bin);

    // http://bitcoin.stackexchange.com/questions/22929/full-example-data-for-scrypt-stratum-client
    reverse_mem(job->prevhash, sizeof(job->prevhash));
    memcpy(job->prevhash_raw, job->prevhash, sizeof(job->prevhash_raw));
    for (int i = 0; i < 8; ++i) {
        reverse_mem(job->prevhash + i * 4, 4);
    }
    job->prevhash_hex = bin2hex(job->prevhash, sizeof(job->prevhash));

    json_t *target_obj = json_object_get(message, "target");
    if (!target_obj || !json_is_string(target_obj))
        return -__LINE__;
    sds target_bin = hex2bin(json_string_value(target_obj));
    if (!target_bin || sdslen(target_bin) != sizeof(job->target)) {
        sdsfree(target_bin);
        return -__LINE__;
    }
    memcpy(job->target, target_bin, sizeof(job->target));
    sdsfree(target_bin);
    job->block_diff = get_share_difficulty(job->target);

    json_t *pool_name_obj = json_object_get(message, "pool_name");
    if (!pool_name_obj || !json_is_string(pool_name_obj))
        return -__LINE__;
    job->pool_name = sdsnew(json_string_value(pool_name_obj));

    json_t *coinbase_message_obj = json_object_get(message, "coinbase_message");
    if (!coinbase_message_obj || !json_is_string(coinbase_message_obj))
        return -__LINE__;
    job->coinbase_message = sdsnew(json_string_value(coinbase_message_obj));

    json_t *coinbase_account_obj = json_object_get(message, "coinbase_account");
    if (!coinbase_account_obj || !json_is_boolean(coinbase_account_obj))
        return -__LINE__;
    job->coinbase_account = json_boolean_value(coinbase_account_obj);

    json_t *coinbaseaux_obj = json_object_get(message, "coinbaseaux");
    if (!coinbaseaux_obj || !json_is_string(coinbaseaux_obj))
        return -__LINE__;
    job->coinbaseaux_bin = hex2bin(json_string_value(coinbaseaux_obj));
    if (job->coinbaseaux_bin == NULL)
        return -__LINE__;

    json_t *coinbase1_obj = json_object_get(message, "coinbase1");
    if (!coinbase1_obj || !json_is_string(coinbase1_obj))
        return -__LINE__;
    job->coinbase1_bin = hex2bin(json_string_value(coinbase1_obj));
    if (job->coinbase1_bin == NULL)
        return -__LINE__;

    json_t *coinbase2_obj = json_object_get(message, "coinbase2");
    if (!coinbase2_obj || !json_is_string(coinbase2_obj))
        return -__LINE__;
    job->coinbase2_hex = sdsnew(json_string_value(coinbase2_obj));
    job->coinbase2_bin = hex2bin(json_string_value(coinbase2_obj));
    if (job->coinbase2_bin == NULL)
        return -__LINE__;

    json_t *merkle = json_object_get(message, "merkle_branch");
    if (!merkle || !json_is_array(merkle))
        return -__LINE__;
    json_incref(merkle);
    job->merkle_json = merkle;

    job->merkle_branch_count = json_array_size(merkle);
    job->merkle_branch = malloc(sizeof(sds) * (job->merkle_branch_count));
    for (size_t i = 0; i < job->merkle_branch_count; ++i) {
        json_t *row = json_array_get(merkle, i);
        if (!row || !json_is_string(row))
            return -__LINE__;
        job->merkle_branch[i] = hex2bin(json_string_value(row));
        if (job->merkle_branch[i] == NULL)
            return -__LINE__;
    }

    json_t *name_obj = json_object_get(message, "main_name");
    if (!name_obj || !json_is_string(name_obj))
        return -__LINE__;
    job->name = sdsnew(json_string_value(name_obj));

    json_t *aux_target_obj = json_object_get(message, "aux_target");
    if (!aux_target_obj || !json_is_string(aux_target_obj))
        return -__LINE__;
    sds aux_target_bin = hex2bin(json_string_value(aux_target_obj));
    if (aux_target_bin && sdslen(aux_target_bin) == 32) {
        job->has_aux_coin = true;
        memcpy(job->aux_target, aux_target_bin, sizeof(job->aux_target));

        json_t *aux_name_obj = json_object_get(message, "aux_name");
        if (!aux_name_obj || !json_is_string(aux_name_obj))
            return -__LINE__;
        job->aux_name = sdsnew(json_string_value(aux_name_obj));

        json_t *aux_hash_obj = json_object_get(message, "aux_hash");
        if (!aux_hash_obj || !json_is_string(aux_hash_obj))
            return -__LINE__;
        job->aux_hash = sdsnew(json_string_value(aux_hash_obj));
    }
    sdsfree(aux_target_bin);

    return 0;
}

static void clear_job(void)
{
    dict_clear(job_dict);
    curr_job = NULL;
}

static int on_job_update(json_t *message)
{
    struct job *job = malloc(sizeof(struct job));
    memset(job, 0, sizeof(struct job));
    int ret = decode_job(message, job);
    if (ret < 0) {
        job_free(job);
        return -__LINE__;
    }

    json_t *clean_jobs_obj = json_object_get(message, "clean_jobs");
    if (!clean_jobs_obj || !json_is_boolean(clean_jobs_obj)) {
        job_free(job);
        return -__LINE__;
    }
    bool clean_jobs = json_boolean_value(clean_jobs_obj);
    if (clean_jobs) {
        log_info("clean job, clear job dict");
        clear_job();
    }

    sds key = sdsnew(job->job_id);
    dict_entry *entry = dict_find(job_dict, key);
    if (entry) {
        sdsfree(key);
        job_free(job);
        log_error("job key: %s duplicate", key);
        return -__LINE__;
    }
    dict_add(job_dict, key, job);
    curr_job = job;
    curr_job_id = job->job_id_num;

    log_info("broadcast job: %s", job->job_id);
    ret = broadcast_job(job, clean_jobs);
    if (ret < 0) {
        log_error("broadcast_job: %s fail", key);
        return -__LINE__;
    }
    last_broadcast = time(NULL);

    return 0;
}

static char *get_sock_cfg(const char *host, int port)
{
    static char str[128];
    bool is_ip = true;
    size_t host_len = strlen(host);
    for (size_t i = 0; i < host_len; ++i) {
        if (!isdigit(host[i]) && host[i] != '.') {
            is_ip = false;
        }
    }
    if (is_ip) {
        snprintf(str, sizeof(str), "tcp@%s:%d", host, port);
        return str;
    }

    char ip[INET6_ADDRSTRLEN];
    struct hostent *hp = gethostbyname(host);
    if (hp == NULL) {
        return NULL;
    }
    if (hp->h_length == 0) {
        return NULL;
    }
    inet_ntop(hp->h_addrtype, hp->h_addr_list[0], ip, sizeof(ip));
    snprintf(str, sizeof(str), "tcp@%s:%d", ip, port);
    return str;
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
    json_object_set_new(message, "method", json_string("agent.subscribe"));

    json_t *params = json_array();
    json_array_append_new(params, json_integer(1));
    json_array_append_new(params, json_integer(worker_id));

    json_object_set_new(message, "params", params);

    send_json(ses, message);
    json_decref(message);

    return 0;
}

static int decode_pkg(nw_ses *ses, void *data, size_t max)
{
    char *s = data;
    for (size_t i = 0; i < max; ++i) {
        if (s[i] == '\n')
            return i + 1;
    }
    return 0;
}

static void on_connect(nw_ses *ses, bool result)
{
    if (result) {
        log_info("connect stratum server: %s success", nw_sock_human_addr(&ses->peer_addr));
        clear_job();
        send_subscribe(ses);
        submit_sync_all();
        last_activity = time(NULL);
    } else {
        log_error("connect stratum server: %s fail", nw_sock_human_addr(&ses->peer_addr));
    }
}

static int on_close(nw_ses *ses)
{
    log_error("stratum server: %s close", nw_sock_human_addr(&ses->peer_addr));
    char *sock_cfg = get_sock_cfg(settings.stratum_host, settings.stratum_port);
    if (sock_cfg == NULL) {
        log_error("get_sock_cfg, host: %s", settings.stratum_host);
        return 0;
    }
    if (nw_sock_cfg_parse(sock_cfg, &ses->peer_addr, &ses->sock_type) < 0) {
        log_error("nw_sock_cfg_parse: %s fail", sock_cfg);
        return 0;
    }

    return 0;
}

static void on_recv_pkg(nw_ses *ses, void *data, size_t size)
{
    json_t *request = json_loadb(data, size - 1, 0, NULL);
    if (request == NULL) {
        goto decode_error;
    }

    char *request_data = data;
    request_data[size - 1] = '\0';
    log_trace("peer: %s, recv: %s", nw_sock_human_addr(&ses->peer_addr), request_data);

    if (json_object_get(request, "id") == NULL) {
        int ret = on_job_update(request);
        if (ret < 0) {
            log_error("on_job_update fail: %d, data: %s", ret, request_data);
        } else {
            log_debug("update job: %s", request_data);
            if (curr_job_message)
                json_decref(curr_job_message);
            json_incref(request);
            curr_job_message = request;
            last_activity = time(NULL);
            last_real_job = time(NULL);
            agent_status = true;
        }
    } else {
        log_debug("recv: %s", request_data);
    }

    json_decref(request);
    return;

decode_error:
    if (request) {
        json_decref(request);
    }
    sds hex = hexdump(data, size - 1);
    log_error("peer: %s decode request fail, request data: \n%s", nw_sock_human_addr(&ses->peer_addr), hex);
    sdsfree(hex);
}

static void on_error_msg(nw_ses *ses, const char *msg)
{
    log_error("peer: %s, error: %s", nw_sock_human_addr(&ses->peer_addr), msg);
}

static int init_clt(void)
{
    nw_clt_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    char *sock_cfg = get_sock_cfg(settings.stratum_host, settings.stratum_port);
    if (sock_cfg == NULL) {
        printf("get_sock_cfg fail, host: %s\n", settings.stratum_host);
        return -__LINE__;
    }
    if (nw_sock_cfg_parse(sock_cfg, &cfg.addr, &cfg.sock_type) < 0) {
        printf("nw_sock_cfg_parse: %s fail\n", sock_cfg);
        return -__LINE__;
    }
    cfg.max_pkg_size = 502400;
    cfg.reconnect_timeout = 3;

    nw_clt_type type;
    memset(&type, 0, sizeof(type));
    type.decode_pkg = decode_pkg;
    type.on_close = on_close;
    type.on_connect = on_connect;
    type.on_recv_pkg = on_recv_pkg;
    type.on_error_msg = on_error_msg;

    clt = nw_clt_create(&cfg, &type, NULL);
    if (clt == NULL)
        return -__LINE__;
    if (nw_clt_start(clt) < 0)
        return -__LINE__;

    return 0;
}

static uint32_t job_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sdslen((sds)key));
}
static int job_dict_key_compare(const void *key1, const void *key2)
{
    return sdscmp((sds)key1, (sds)key2);
}
static void job_dict_key_free(void *key)
{
    sdsfree((sds)key);
}
static void job_dict_val_free(void *val)
{
    job_free((struct job *)val);
}

static int init_dict(void)
{
    dict_types type_job;
    memset(&type_job, 0, sizeof(type_job));
    type_job.hash_function  = job_dict_hash_func;
    type_job.key_compare    = job_dict_key_compare;
    type_job.key_destructor = job_dict_key_free;
    type_job.val_destructor = job_dict_val_free;

    job_dict = dict_create(&type_job, 64);
    if (job_dict == NULL)
        return -__LINE__;

    return 0;
}

static double get_sha256_bignum(const char *hash)
{
    double x = (uint8_t)(hash[0]);
    for (int i = 1; i < 32; ++i) {
        x = x * 256 + (uint8_t)(hash[i]);
    }
    return x;
}

int init_diff(void)
{
    char *diff1_hex = "00000000FFFF0000000000000000000000000000000000000000000000000000";
    sds diff1_hash = hex2bin(diff1_hex);
    diff1_bignum = get_sha256_bignum(diff1_hash);
    sdsfree(diff1_hash);

    return 0;
}

static void on_timer(nw_timer *timer, void *privdata)
{
    time_t now = time(NULL);
    if (nw_clt_connected(clt)) {
        last_connected = now;
        if (now - last_activity >= 120) {
            log_error("last_activity: %ld, idle time to long, try reconnect", last_activity);
            nw_clt_close(clt);
            nw_clt_start(clt);
            if (agent_status && now - last_real_job >= settings.connect_timeout) {
                log_error("last_real_job: %ld, connect timeout, shutdown", last_real_job);
                agent_status = false;
                close_all_connection();
                return;
            }
        }
    } else {
        if (agent_status && last_connected > 0 && now - last_connected >= settings.connect_timeout) {
            log_error("last_connected: %ld, connect timeout, shutdown", last_connected);
            agent_status = false;
            close_all_connection();
            return;
        }
    }

    if (curr_job_message && last_broadcast && (now - last_broadcast) > settings.broadcast_timeout) {
        log_error("broadcast job timeout");
        struct job *job = malloc(sizeof(struct job));
        memset(job, 0, sizeof(struct job));
        int ret = decode_job(curr_job_message, job);
        if (ret < 0) {
            log_error("decode_job fail: %d", ret);
            job_free(job);
            return;
        }

        job->job_id_num = curr_job_id + 1;
        job->is_fake = true;
        snprintf(job->job_id, sizeof(job->job_id), "%x", job->job_id_num);
        sds key = sdsnew(job->job_id);
        dict_add(job_dict, key, job);
        curr_job = job;
        curr_job_id = job->job_id_num;

        log_info("broadcast fake job: %s", job->job_id);
        ret = broadcast_job(job, false);
        if (ret < 0) {
            log_error("broadcast_job: %s fail", key);
            return;
        }
        last_broadcast = time(NULL);
    }
}

int init_timer(void)
{
    nw_timer_set(&timer, 1.0, true, on_timer, NULL);
    nw_timer_start(&timer);

    return 0;
}

int init_job(void)
{
    ERR_RET(init_clt());
    ERR_RET(init_dict());
    ERR_RET(init_diff());
    ERR_RET(init_timer());

    return 0;
}

struct job *get_curr_job(void)
{
    return curr_job;
}

struct job *find_job(const char *job_id)
{
    sds key = sdsnew(job_id);
    dict_entry *entry = dict_find(job_dict, key);
    if (entry) {
        sdsfree(key);
        return entry->val;
    }
    sdsfree(key);
    return NULL;
}

sds get_real_coinbase1(struct job *job, char *user, uint32_t nonce_id)
{
    size_t left_size = 100 - 5 - 1 - 19;
    if (sdslen(job->coinbaseaux_bin)) {
        left_size -= (1 + sdslen(job->coinbaseaux_bin));
    }

    sds msg = sdsempty();
    msg = sdscat(msg, "/");
    left_size -= 1;
    if (sdslen(job->pool_name) && sdslen(job->pool_name) < left_size) {
        msg = sdscat(msg, job->pool_name);
        msg = sdscat(msg, "/");
        left_size -= (sdslen(job->pool_name) + 1);
    }
    if (sdslen(job->coinbase_message) && sdslen(job->coinbase_message) < left_size) {
        msg = sdscat(msg, job->coinbase_message);
        msg = sdscat(msg, "/");
        left_size -= (sdslen(job->coinbase_message) + 1);
    }
    if (job->coinbase_account) {
        sds userinfo = sdsempty();
        userinfo = sdscatprintf(userinfo, "Mined by %s", user);
        if (sdslen(userinfo) < left_size) {
            msg = sdscat(msg, userinfo);
            msg = sdscat(msg, "/");
            left_size -= (sdslen(userinfo) + 1);
        }
        sdsfree(userinfo);
    }

    char script[1024];
    void *p = script;
    size_t left = sizeof(script);
    pack_oppushint_le(&p, &left, job->height);
    if (sdslen(msg) > 1) {
        pack_oppush(&p, &left, msg, sdslen(msg));
    }
    sdsfree(msg);
    if (sdslen(job->coinbaseaux_bin)) {
        pack_oppush(&p, &left, job->coinbaseaux_bin, sdslen(job->coinbaseaux_bin)); // coinbaseaux
    }
    pack_char(&p, &left, 18);
    pack_uint16_le(&p, &left, job->job_id_num);
    pack_uint32_le(&p, &left, worker_id);
    pack_uint32_le(&p, &left, nonce_id);

    int extra_nonce_size = get_extra_nonce_size();
    uint32_t script_real_size = sizeof(script) - left + extra_nonce_size;

    char coinbase1[1024];
    p = coinbase1;
    left = sizeof(coinbase1);
    pack_buf(&p, &left, job->coinbase1_bin, sdslen(job->coinbase1_bin));
    pack_varint_le(&p, &left, script_real_size);
    pack_buf(&p, &left, script, script_real_size - extra_nonce_size);

    return sdsnewlen(coinbase1, sizeof(coinbase1) - left);
}

double get_share_difficulty(const char *header_hash)
{
    double hash_bignum = get_sha256_bignum(header_hash);
    return to_fixed(diff1_bignum / hash_bignum, 4);
}

int is_stratum_ok(void)
{
    return agent_status;
}

int submit_sync(uint32_t miner_id, uint32_t nonce_id, char *extra_nonce1, int difficulty)
{
    json_t *message = json_object();
    json_object_set_new(message, "id", json_integer(current_timestamp() * 1000));
    json_object_set_new(message, "method", json_string("agent.sync"));

    json_t *params = json_array();
    json_array_append_new(params, json_integer(miner_id));
    json_array_append_new(params, json_integer(nonce_id));
    json_array_append_new(params, json_string(extra_nonce1));
    json_array_append_new(params, json_integer(difficulty));

    json_object_set_new(message, "params", params);

    send_json(&clt->ses, message);
    json_decref(message);

    return 0;
}

int submit_share(uint32_t miner_id, json_t *share, uint32_t version_mask_svr, uint32_t version_mask_miner, uint32_t version_mask)
{
    json_t *message = json_object();
    json_object_set_new(message, "id", json_integer(current_timestamp() * 1000));
    json_object_set_new(message, "method", json_string("agent.submit"));

    json_t *params = json_array();
    json_array_append_new(params, json_integer(miner_id));
    json_array_append(params, json_array_get(share, 0));
    json_array_append(params, json_array_get(share, 1));
    json_array_append(params, json_array_get(share, 2));
    json_array_append(params, json_array_get(share, 3));
    json_array_append(params, json_array_get(share, 4));
    json_array_append_new(params, json_integer(version_mask_svr));
    json_array_append_new(params, json_integer(version_mask_miner));
    json_array_append_new(params, json_integer(version_mask));

    json_object_set_new(message, "params", params);

    send_json(&clt->ses, message);
    json_decref(message);

    return 0;
}

int submit_event(const char *user, const char *worker, const char *event)
{
    json_t *message = json_object();
    json_object_set_new(message, "id", json_integer(current_timestamp() * 1000));
    json_object_set_new(message, "method", json_string("agent.event"));

    json_t *params = json_array();
    json_array_append_new(params, json_string(user));
    json_array_append_new(params, json_string(worker));
    json_array_append_new(params, json_string(event));

    json_object_set_new(message, "params", params);

    send_json(&clt->ses, message);
    json_decref(message);

    return 0;
}

int submit_status(time_t timestamp, int connections)
{
    json_t *message = json_object();
    json_object_set_new(message, "id", json_integer(current_timestamp() * 1000));
    json_object_set_new(message, "method", json_string("agent.status"));

    json_t *params = json_array();
    json_array_append_new(params, json_integer(timestamp));
    json_array_append_new(params, json_integer(connections));

    json_object_set_new(message, "params", params);

    send_json(&clt->ses, message);
    json_decref(message);

    return 0;
}

int send_data(const char *data, size_t size)
{
    return nw_ses_send(&clt->ses, data, size);
}

