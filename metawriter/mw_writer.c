/*
 * Description: 
 *     History: yang@haipo.me, 2016/12/04, create
 */

# include "mw_config.h"
# include "mw_writer.h"
# include "nw_job.h"
# include "ut_pack.h"
# include "ut_signal.h"
# include "ut_rpc_cmd.h"
# include <math.h>

static rpc_svr *svr;
static rpc_clt *brother;
static nw_timer timer;
static nw_job *job;
static dict_t *dict_keys;
static dict_t *dict_recv;
static dict_t *dict_share;
static dict_t *dict_monitor_int;
static dict_t *dict_monitor_float;
static dict_t *dict_worker;

static int flush_cost;
static bool flush_error;
static time_t last_flush;
static time_t flush_error_start;
static time_t last_clear_worker;

struct keys_val {
    time_t timestamp;
};

struct recv_key {
    char hash[32];
};

struct recv_val {
    time_t timestamp;
};

struct share_val {
    uint64_t num;
    uint64_t pow;
    double   goal;
};

struct monitor_int_val {
    uint64_t sum;
};

struct monitor_float_val {
    double   sum;
};

struct job_privdata {
    redisContext *store;
};

struct worker_key {
    char user[MAX_USER_NAME_LEN + 1];
    char worker[MAX_WORKER_NAME_LEN + 1];
    char name[10];
};

# define JOB_PROCESS_NUM 50
# define JOB_PENDING_NUM 5000000

static int add_job(const char *fmt, ...);
static int add_job_without_limit(const char *fmt, ...);

static int update_new_block(sds user, sds worker, sds name, sds hash)
{
    json_t *message = json_object();
    json_object_set_new(message, "user", json_string(user));
    json_object_set_new(message, "worker", json_string(worker));
    json_object_set_new(message, "name", json_string(name));
    json_object_set_new(message, "hash", json_string(hash));

    char *dump = json_dumps(message, 0);
    json_decref(message);
    int ret = add_job_without_limit("RPUSH newblock %s", dump);
    free(dump);

    return ret;
}

static int process_cmd_meta_block(rpc_pkg *pkg)
{
    void *data = pkg->body;
    size_t size = pkg->body_size;

    char rand[32];
    ERR_RET(unpack_buf(&data, &size, rand, sizeof(rand)));
    sds user, worker, name, hash;
    while (size > 0) {
        user    = NULL;
        worker  = NULL;
        name    = NULL;
        hash    = NULL;

        if (unpack_varstr(&data, &size, &user) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &worker) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &name) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &hash) < 0)
            goto error;
        log_vip("block info, user: %s worker: %s name: %s hash: %s", user, worker, name, hash);

        int ret = update_new_block(user, worker, name, hash);
        if (ret < 0) {
            log_fatal("update_new_block fail: %d", ret);
        }

        sdsfree(user);
        sdsfree(worker);
        sdsfree(name);
        sdsfree(hash);
    }

    return 0;

error:
    sdsfree(user);
    sdsfree(worker);
    sdsfree(name);
    sdsfree(hash);
    return -__LINE__;
}

static int update_new_worker(sds user, sds worker, sds name)
{
    struct worker_key key;
    strncpy(key.user, user, sizeof(key.user));
    strncpy(key.worker, worker, sizeof(key.worker));
    strncpy(key.name, name, sizeof(key.name));
    if (dict_find(dict_worker, &key) != NULL) {
        return 0;
    }
    dict_add(dict_worker, &key, NULL);

    json_t *message = json_object();
    json_object_set_new(message, "user", json_string(user));
    json_object_set_new(message, "worker", json_string(worker));
    json_object_set_new(message, "coin", json_string(name));

    char *dump = json_dumps(message, 0);
    json_decref(message);
    int ret = add_job_without_limit("RPUSH newworker %s", dump);
    free(dump);

    return ret;
}

static int update_new_event(sds user, sds worker, sds name, sds peer, sds event)
{
    json_t *message = json_object();
    json_object_set_new(message, "user", json_string(user));
    json_object_set_new(message, "worker", json_string(worker));
    json_object_set_new(message, "coin", json_string(name));
    json_object_set_new(message, "peer", json_string(peer));
    json_object_set_new(message, "event", json_string(event));

    char *dump = json_dumps(message, 0);
    json_decref(message);
    int ret = add_job_without_limit("RPUSH newevent %s", dump);
    free(dump);

    return ret;
}

static int process_cmd_meta_event(rpc_pkg *pkg)
{
    void *data = pkg->body;
    size_t size = pkg->body_size;

    char rand[32];
    ERR_RET(unpack_buf(&data, &size, rand, sizeof(rand)));
    sds user, worker, name, peer, event;
    while (size > 0) {
        user    = NULL;
        worker  = NULL;
        name    = NULL;
        peer    = NULL;
        event   = NULL;

        if (unpack_varstr(&data, &size, &user) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &worker) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &name) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &peer) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &event) < 0)
            goto error;
        log_trace("event info, user: %s worker: %s name: %s peer: %s event: %s", user, worker, name, peer, event);

        if (strcmp(event, "connected") == 0) {
            int ret = update_new_worker(user, worker, name);
            if (ret < 0) {
                log_error("update_new_worker fail: %d", ret);
            }
        }
        int ret = update_new_event(user, worker, name, peer, event);
        if (ret < 0) {
            log_error("update_new_event fail: %d", ret);
        }

        sdsfree(user);
        sdsfree(worker);
        sdsfree(name);
        sdsfree(peer);
        sdsfree(event);
    }

    return 0;

error:
    sdsfree(user);
    sdsfree(worker);
    sdsfree(name);
    sdsfree(peer);
    sdsfree(event);
    return -__LINE__;
}

static int update_share(const sds key, const sds name, uint64_t num, uint64_t pow, double goal)
{
    sds real_key = sdsempty();
    real_key = sdscatprintf(real_key, "%s/%s", key, name);
    dict_entry *entry = dict_find(dict_share, real_key);
    if (entry == NULL) {
        struct share_val val = { .num = num, .pow = pow, .goal = goal };
        dict_add(dict_share, real_key, &val);
        sdsfree(real_key);
        return 0;
    }
    struct share_val *val = entry->val;
    val->num += num;
    val->pow += pow;
    val->goal += goal;
    sdsfree(real_key);
    return 0;
}

static int update_monitor_int(sds key, sds host, sds name, uint64_t sum)
{
    sds real_key = sdsempty();
    real_key = sdscatprintf(real_key, "%s/%s/%s", key, host, name);
    dict_entry *entry = dict_find(dict_monitor_int, real_key);
    if (entry == NULL) {
        struct monitor_int_val val = { .sum = sum };
        dict_add(dict_monitor_int, real_key, &val);
        sdsfree(real_key);
        return 0;
    }
    struct monitor_int_val *val = entry->val;
    val->sum += sum;
    sdsfree(real_key);
    return 0;
}

static int update_monitor_float(sds key, sds host, sds name, double sum)
{
    sds real_key = sdsempty();
    real_key = sdscatprintf(real_key, "%s/%s/%s", key, host, name);
    dict_entry *entry = dict_find(dict_monitor_float, real_key);
    if (entry == NULL) {
        struct monitor_float_val val = { .sum = sum };
        dict_add(dict_monitor_float, real_key, &val);
        sdsfree(real_key);
        return 0;
    }
    struct monitor_float_val *val = entry->val;
    val->sum += sum;
    sdsfree(real_key);
    return 0;

}

static int process_cmd_meta_share(rpc_pkg *pkg)
{
    void *data = pkg->body;
    size_t size = pkg->body_size;

    char rand[32];
    ERR_RET(unpack_buf(&data, &size, rand, sizeof(rand)));

    sds key, host, name;
    uint64_t num, pow;
    double goal;
    while (size > 0) {
        key     = NULL;
        host    = NULL;
        name    = NULL;

        if (unpack_varstr(&data, &size, &key) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &host) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &name) < 0)
            goto error;
        if (unpack_varint_le(&data, &size, &num) < 0)
            goto error;
        if (unpack_varint_le(&data, &size, &pow) < 0)
            goto error;
        if (unpack_double_le(&data, &size, &goal) < 0)
            goto error;

        log_trace("share info, key: %s host: %s name: %s num: %"PRIu64" pow: %"PRIu64" goal:%.16g", key, host, name, num, pow, goal);
        update_share(key, name, num, pow, goal);

        sdsfree(key);
        sdsfree(host);
        sdsfree(name);
    }

    return 0;

error:
    sdsfree(key);
    sdsfree(host);
    sdsfree(name);
    return -__LINE__;
}

static int process_cmd_meta_monitor_int(rpc_pkg *pkg)
{
    void *data = pkg->body;
    size_t size = pkg->body_size;

    char rand[32];
    ERR_RET(unpack_buf(&data, &size, rand, sizeof(rand)));

    sds key, host, name;
    uint64_t sum;
    while (size > 0) {
        key     = NULL;
        host    = NULL;
        name    = NULL;

        if (unpack_varstr(&data, &size, &key) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &host) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &name) < 0)
            goto error;
        if (unpack_varint_le(&data, &size, &sum) < 0)
            goto error;
        log_trace("monitor info, key: %s host: %s name: %s num: %"PRIu64"", key, host, name, sum);

        update_monitor_int(key, host, name, sum);

        sdsfree(key);
        sdsfree(host);
        sdsfree(name);
    }

    return 0;

error:
    sdsfree(key);
    sdsfree(host);
    sdsfree(name);
    return -__LINE__;
}

static int process_cmd_meta_monitor_float(rpc_pkg *pkg)
{
    void *data = pkg->body;
    size_t size = pkg->body_size;

    char rand[32];
    ERR_RET(unpack_buf(&data, &size, rand, sizeof(rand)));

    sds key, host, name;
    double sum;
    while (size > 0) {
        key     = NULL;
        host    = NULL;
        name    = NULL;

        if (unpack_varstr(&data, &size, &key) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &host) < 0)
            goto error;
        if (unpack_varstr(&data, &size, &name) < 0)
            goto error;
        if (unpack_double_le(&data, &size, &sum) < 0)
            goto error;

        log_trace("monitor float info, key: %s host: %s name: %s sum:%.16g", key, host, name, sum);
        update_monitor_float(key, host, name, sum);

        sdsfree(key);
        sdsfree(host);
        sdsfree(name);    
    }

    return 0;

error:
    sdsfree(key);
    sdsfree(host);
    sdsfree(name);
    return -__LINE__;
}

static int send_hash_to_brother(char *hash)
{
    if (!settings.has_brother) {
        return 0;
    }

    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.command     = CMD_META_HASH;
    pkg.pkg_type    = RPC_PKG_TYPE_PUSH;
    pkg.body        = hash;
    pkg.body_size   = 32;

    return rpc_clt_send(brother, &pkg);
}

static int process_cmd_meta_hash(rpc_pkg *pkg)
{
    if (pkg->body_size != 32)
        return -__LINE__;

    struct recv_key key;
    memcpy(key.hash, pkg->body, 32);
    struct recv_val val = { .timestamp = time(NULL) };
    dict_add(dict_recv, &key, &val);
    sds hex = bin2hex(key.hash, sizeof(key.hash));
    log_trace("meta hash: %s processed", hex);
    sdsfree(hex);

    return 0;
}

static void svr_on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    log_trace("recv pkg cmd: %u from: %s", pkg->command, nw_sock_human_addr(&ses->peer_addr));
    struct recv_key key;
    if (pkg->command != CMD_META_HASH) {
        sha256(pkg->body, pkg->body_size, key.hash);
        if (dict_find(dict_recv, &key)) {
            log_trace("duplicate pkg from: %s", nw_sock_human_addr(&ses->peer_addr));
            return;
        }
    }

    int ret;
    switch (pkg->command) {
    case CMD_META_BLOCK:
        ret = process_cmd_meta_block(pkg);
        break;
    case CMD_META_EVENT:
        ret = process_cmd_meta_event(pkg);
        break;
    case CMD_META_SHARE:
        ret = process_cmd_meta_share(pkg);
        break;
    case CMD_META_MONITOR_INT:
        ret = process_cmd_meta_monitor_int(pkg);
        break;
    case CMD_META_HASH:
        ret = process_cmd_meta_hash(pkg);
        break;
    case CMD_META_MONITOR_FLOAT:
        ret = process_cmd_meta_monitor_float(pkg);
        break;
    default:
        log_error("unknown cmd: %u from: %s", pkg->command, nw_sock_human_addr(&ses->peer_addr));
        return;
    }

    if (ret < 0) {
        sds hex = hexdump(pkg->body, pkg->body_size);
        log_fatal("process cmd: %u fail: %d, data:\n%s", pkg->command, ret, hex);
        sdsfree(hex);
        return;
    }

    if (pkg->command != CMD_META_HASH) {
        struct recv_val val = { .timestamp = time(NULL) };
        dict_add(dict_recv, &key, &val);
        sds hex = bin2hex(key.hash, sizeof(key.hash));
        log_trace("meta hash: %s processed", hex);
        sdsfree(hex);
        send_hash_to_brother(key.hash);
    }
}

static void svr_on_new_connection(nw_ses *ses)
{
    log_info("new connection from: %"PRIu64":%s", ses->id, nw_sock_human_addr(&ses->peer_addr));
}

static void svr_on_connection_close(nw_ses *ses)
{
    log_info("connection: %"PRIu64":%s close", ses->id, nw_sock_human_addr(&ses->peer_addr));
}

static int init_svr(void)
{
    nw_svr_cfg cfg;
    nw_svr_bind bind;
    memset(&cfg, 0, sizeof(cfg));
    cfg.bind_count = 1;
    if (nw_sock_cfg_parse(MW_WORKER_BIND, &bind.addr, &bind.sock_type) < 0)
        return -__LINE__;

    cfg.bind_arr = &bind;
    cfg.max_pkg_size = settings.svr.max_pkg_size;

    rpc_svr_type type;
    type.on_recv_pkg = svr_on_recv_pkg;
    type.on_new_connection = svr_on_new_connection;
    type.on_connection_close = svr_on_connection_close;

    svr = rpc_svr_create(&cfg, &type);
    if (svr == NULL)
        return -__LINE__;
    if (rpc_svr_start(svr) < 0)
        return -__LINE__;
    
    return 0;
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
    log_trace("recv pkg cmd: %u from: %s", pkg->command, nw_sock_human_addr(&ses->peer_addr));
}

int init_brother()
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

static uint32_t sds_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sdslen((sds)key));
}

static int sds_dict_key_compare(const void *key1, const void *key2)
{
    return sdscmp((sds)key1, (sds)key2);
}

static void *sds_dict_key_dup(const void *key)
{
    return sdsdup((sds)key);
}

static void sds_dict_key_free(void *key)
{
    sdsfree((sds)key);
}

static void *keys_dict_val_dup(const void *val)
{
    struct keys_val *obj = malloc(sizeof(struct keys_val));
    memcpy(obj, val, sizeof(struct keys_val));
    return obj;
}

static void keys_dict_val_free(void *val)
{
    free(val);
}

static uint32_t recv_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sizeof(struct recv_key));
}

static int recv_dict_key_compare(const void *key1, const void *key2)
{
    return memcmp(key1, key2, sizeof(struct recv_key));
}

static void *recv_dict_key_dup(const void *key)
{
    struct recv_key *obj = malloc(sizeof(struct recv_key));
    memcpy(obj, key, sizeof(struct recv_key));
    return obj;
}

static void recv_dict_key_free(void *key)
{
    free(key);
}

static void *recv_dict_val_dup(const void *val)
{
    struct recv_val *obj = malloc(sizeof(struct recv_val));
    memcpy(obj, val, sizeof(struct recv_val));
    return obj;
}

static void recv_dict_val_free(void *val)
{
    free(val);
}

static void *share_dict_val_dup(const void *val)
{
    struct share_val *obj = malloc(sizeof(struct share_val));
    memcpy(obj, val, sizeof(struct share_val));
    return obj;
}

static void share_dict_val_free(void *val)
{
    free(val);
}

static void *monitor_dict_int_dup(const void *val)
{
    struct monitor_int_val *obj = malloc(sizeof(struct monitor_int_val));
    memcpy(obj, val, sizeof(struct monitor_int_val));
    return obj;
}

static void monitor_dict_int_free(void *val)
{
    free(val);
}

static void *monitor_dict_float_dup(const void *val)
{
    struct monitor_float_val *obj = malloc(sizeof(struct monitor_float_val));
    memcpy(obj, val, sizeof(struct monitor_float_val));
    return obj;
}

static void monitor_dict_float_free(void *val)
{
    free(val);
}

static uint32_t worker_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sizeof(struct worker_key));
}

static int worker_dict_key_compare(const void *key1, const void *key2)
{
    return memcmp(key1, key2, sizeof(struct worker_key));
}

static void *worker_dict_key_dup(const void *key)
{
    struct worker_key *obj = malloc(sizeof(struct worker_key));
    memcpy(obj, key, sizeof(struct worker_key));
    return obj;
}

static void worker_dict_key_free(void *key)
{
    free(key);
}

static int init_dict(void)
{
    dict_types type;

    memset(&type, 0, sizeof(type));
    type.hash_function  = sds_dict_hash_func;
    type.key_compare    = sds_dict_key_compare;
    type.key_dup        = sds_dict_key_dup;
    type.key_destructor = sds_dict_key_free;
    type.val_dup        = keys_dict_val_dup;
    type.val_destructor = keys_dict_val_free;

    dict_keys = dict_create(&type, 64);
    if (dict_keys == NULL)
        return -__LINE__;

    memset(&type, 0, sizeof(type));
    type.hash_function  = recv_dict_hash_func;
    type.key_compare    = recv_dict_key_compare;
    type.key_dup        = recv_dict_key_dup;
    type.key_destructor = recv_dict_key_free;
    type.val_dup        = recv_dict_val_dup;
    type.val_destructor = recv_dict_val_free;

    dict_recv = dict_create(&type, 64);
    if (dict_recv == NULL)
        return -__LINE__;

    memset(&type, 0, sizeof(type));
    type.hash_function  = sds_dict_hash_func;
    type.key_compare    = sds_dict_key_compare;
    type.key_dup        = sds_dict_key_dup;
    type.key_destructor = sds_dict_key_free;
    type.val_dup        = share_dict_val_dup;
    type.val_destructor = share_dict_val_free;

    dict_share = dict_create(&type, 64);
    if (dict_share == NULL)
        return -__LINE__;

    memset(&type, 0, sizeof(type));
    type.hash_function  = sds_dict_hash_func;
    type.key_compare    = sds_dict_key_compare;
    type.key_dup        = sds_dict_key_dup;
    type.key_destructor = sds_dict_key_free;
    type.val_dup        = monitor_dict_int_dup;
    type.val_destructor = monitor_dict_int_free;

    dict_monitor_int = dict_create(&type, 64);
    if (dict_monitor_int == NULL)
        return -__LINE__;

    memset(&type, 0, sizeof(type));
    type.hash_function  = sds_dict_hash_func;
    type.key_compare    = sds_dict_key_compare;
    type.key_dup        = sds_dict_key_dup;
    type.key_destructor = sds_dict_key_free;
    type.val_dup        = monitor_dict_float_dup;
    type.val_destructor = monitor_dict_float_free;

    dict_monitor_float = dict_create(&type, 64);
    if (dict_monitor_float == NULL)
        return -__LINE__;

    memset(&type, 0, sizeof(type));
    type.hash_function  = worker_dict_hash_func;
    type.key_compare    = worker_dict_key_compare;
    type.key_dup        = worker_dict_key_dup;
    type.key_destructor = worker_dict_key_free;

    dict_worker = dict_create(&type, 64);
    if (dict_worker == NULL)
        return -__LINE__;

    return 0;
}

static void *on_job_init(void)
{
    struct job_privdata *obj = malloc(sizeof(struct job_privdata));
    if (obj == NULL)
        return NULL;
    obj->store = redis_connect(&settings.redis);
    if (obj->store == NULL) {
        log_error("redis connect fail");
        free(obj);
        return NULL;
    }
    return obj;
}

static redisReply *redisFormattedCommand(redisContext *c, const char *cmd)
{
    void *reply;
    if (redisAppendFormattedCommand(c, cmd, strlen(cmd)) != REDIS_OK)
        return NULL;
    if (redisGetReply(c, &reply) != REDIS_OK)
        return NULL;
    return reply;
}

static void on_job(nw_job_entry *entry, void *privdata)
{
    uint32_t error_cnt = 0;
    struct job_privdata *obj = privdata;
    while (true) {
        if (obj->store == NULL) {
            log_info("redis connection lost, try connect");
            obj->store = redis_connect(&settings.redis);
            if (obj->store == NULL) {
                log_error("redis connect fail");
                usleep(1000 * 1000);
                continue;
            }
        }

        redisReply *reply = redisFormattedCommand(obj->store, entry->request);
        if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
            if (++error_cnt % 60 == 0) {
                log_fatal("redisFormattedCommand fail: %d, %s, cmd: %s", obj->store->err, strerror(errno), (char *)entry->request);
            }
            if (reply == NULL) {
                log_error("redisFormattedCommand fail: %d, %s, cmd: %s", obj->store->err, strerror(errno), (char *)entry->request);
            } else {
                log_error("redisFormattedCommand fail: %d, %s, %s, cmd: %s", obj->store->err, reply->str, strerror(errno), (char *)entry->request);
                freeReplyObject(reply);
            }
            redisFree(obj->store);
            obj->store = NULL;
            usleep(1000 * 1000);
            continue;
        }
        freeReplyObject(reply);

        break;
    }
}

static void on_job_cleanup(nw_job_entry *entry)
{
    free(entry->request);
}

static void on_job_release(void *privdata)
{
    struct job_privdata *obj = privdata;
    redisFree(obj->store);
    free(obj);
}

static int add_job_v(const char *fmt, va_list ap)
{
    char *cmd;
    int len = redisvFormatCommand(&cmd, fmt, ap);
    if (len < 0) {
        log_error("redisvFormatCommand fail: %d", len);
        return -__LINE__;
    }
    int ret = nw_job_add(job, 0, cmd);
    if (ret < 0) {
        log_error("nw_job_add fail: %d", ret);
        free(cmd);
        return -__LINE__;
    }

    return 0;
}

static int add_job(const char *fmt, ...)
{
    if (job->request_count >= JOB_PENDING_NUM && !signal_exit)
        return -__LINE__;

    va_list ap;
    va_start(ap, fmt);
    int ret = add_job_v(fmt, ap);
    va_end(ap);

    return ret;
}

static int add_key(time_t now, const char *fmt, ...)
{
    sds key = sdsempty();
    va_list ap;
    va_start(ap, fmt);
    key = sdscatvprintf(key, fmt, ap);
    va_end(ap);

    dict_entry *entry = dict_find(dict_keys, key);
    if (!entry) {
        log_trace("add mining key: %s", key);
        if (add_job("SADD mining:keys %s", key) == 0) {
            struct keys_val val = { .timestamp = now };
            dict_add(dict_keys, key, &val);
        }
        sdsfree(key);
        return 0;
    }

    struct keys_val *val = entry->val;
    if (now - val->timestamp > settings.key_expire) {
        log_trace("add mining key: %s", key);
        if (add_job("SADD mining:keys %s", key) == 0) {
            val->timestamp = now;
        }
    }

    sdsfree(key);
    return 0;
}

static int add_job_without_limit(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = add_job_v(fmt, ap);
    va_end(ap);

    return ret;
}

static int init_job(void)
{
    nw_job_type type;
    memset(&type, 0, sizeof(type));
    type.on_init    = on_job_init;
    type.on_job     = on_job;
    type.on_cleanup = on_job_cleanup;
    type.on_release = on_job_release;

    job = nw_job_create(&type, JOB_PROCESS_NUM);
    if (job == NULL)
        return -__LINE__;

    return 0;
}

static void check_dict_recv(time_t now)
{
    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(dict_recv);
    while ((entry = dict_next(iter)) != NULL) {
        struct recv_val *val = entry->val;
        if (now - val->timestamp > settings.dup_timeout) {
            dict_delete(dict_recv, entry->key);
        }
    }
    dict_release_iterator(iter);
}

static int flush_share(time_t start)
{
    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(dict_share);
    while ((entry = dict_next(iter)) != NULL) {
        struct share_val *val = entry->val;
        if (val->num == 0) {
            dict_delete(dict_share, entry->key);
            continue;
        }
        sds real_key = entry->key;
        int count;
        sds *tokens = sdssplitlen(real_key, sdslen(real_key), "/", 1, &count);
        if (count != 2) {
            log_error("invalid share key: %s", real_key);
            sdsfreesplitres(tokens, count);
            dict_delete(dict_share, entry->key);
            continue;
        }
        sds key  = tokens[0];
        sds coin = tokens[1];
        log_info("share coin: %s key: %s %"PRIu64" %"PRIu64" goal:%.16g", coin, key, val->num, val->pow, val->goal);

        int ret;
        add_key(start, "%s:s:%s", coin, key);
        ret = add_job("HINCRBY %s:s:%s %ld %"PRIu64, coin, key, start, val->num);
        if (ret < 0) {
            dict_release_iterator(iter);
            sdsfreesplitres(tokens, count);
            return ret;
        }
        val->num = 0;

        if (val->pow) {
            add_key(start, "%s:p:%s", coin, key);
            ret = add_job_without_limit("HINCRBY %s:p:%s %ld %"PRIu64, coin, key, start, val->pow);
            if (ret < 0) {
                dict_release_iterator(iter);
                sdsfreesplitres(tokens, count);
                return ret;
            }
            val->pow = 0;
        }

        if (fabs(val->goal) > 1e-15) {
            add_key(start, "%s:g:%s", coin, key);
            ret = add_job_without_limit("HINCRBYFLOAT %s:g:%s %"PRIu64" %.16g", coin, key, start, val->goal);
            if (ret < 0) {
                dict_release_iterator(iter);
                sdsfreesplitres(tokens, count);
                return ret;
            }
            val->goal = 0;
        }

        sdsfreesplitres(tokens, count);
    }
    dict_release_iterator(iter);

    return 0;
}

static int flush_monitor_int(time_t start)
{
    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(dict_monitor_int);
    while ((entry = dict_next(iter)) != NULL) {
        struct monitor_int_val *val = entry->val;
        if (val->sum == 0) {
            dict_delete(dict_monitor_int, entry->key);
            continue;
        }
        sds real_key = entry->key;
        int count;
        sds *tokens = sdssplitlen(real_key, sdslen(real_key), "/", 1, &count);
        if (count != 3) {
            log_error("invalid monitor key: %s", real_key);
            sdsfreesplitres(tokens, count);
            dict_delete(dict_monitor_int, entry->key);
            continue;
        }
        sds key  = tokens[0];
        sds host = tokens[1];
        sds coin = tokens[2];
        log_info("monitor coin: %s host: %s key: %s %"PRIu64, coin, host, key, val->sum);

        int ret;
        ret = add_job("HINCRBY %s:m:%s %ld %"PRIu64, coin, key, start, val->sum);
        if (ret < 0) {
            dict_release_iterator(iter);
            sdsfreesplitres(tokens, count);
            return ret;
        }

        ret = add_job_without_limit("HINCRBY %s:mh:%s:%s %ld %"PRIu64, coin, host, key, start, val->sum);
        if (ret < 0) {
            dict_release_iterator(iter);
            sdsfreesplitres(tokens, count);
            return ret;
        }

        val->sum = 0;

        ret = add_job_without_limit("SADD %s:mk:%s %s", coin, key, host);
        if (ret < 0) {
            dict_release_iterator(iter);
            sdsfreesplitres(tokens, count);
            return ret;
        }

        ret = add_job_without_limit("SADD monitor:keys %s:m:%s", coin, key);
        if (ret < 0) {
            dict_release_iterator(iter);
            sdsfreesplitres(tokens, count);
            return ret;
        }

        sdsfreesplitres(tokens, count);
    }
    dict_release_iterator(iter);

    return 0;
}

static int flush_monitor_float(time_t start)
{
    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(dict_monitor_float);
    while ((entry = dict_next(iter)) != NULL) {
        struct monitor_float_val *val = entry->val;
        if (fabs(val->sum) <= 1e-15) {
            dict_delete(dict_monitor_float, entry->key);
            continue;
        }
        sds real_key = entry->key;
        int count;
        sds *tokens = sdssplitlen(real_key, sdslen(real_key), "/", 1, &count);
        if (count != 3) {
            log_error("invalid share key: %s", real_key);
            sdsfreesplitres(tokens, count);
            dict_delete(dict_monitor_float, entry->key);
            continue;
        }
        sds key  = tokens[0];
        sds host = tokens[1];
        sds coin = tokens[2];
        log_info("monitor float coin: %s host:%s key: %s sum:%.16g", coin, host, key, val->sum);

        int ret;
        ret = add_job("HINCRBYFLOAT %s:m:%s %ld %.16g", coin, key, start, val->sum);
        if (ret < 0) {
            dict_release_iterator(iter);
            sdsfreesplitres(tokens, count);
            return ret;
        }

        ret = add_job_without_limit("HINCRBYFLOAT %s:mh:%s:%s %ld %.16g", coin, host, key, start, val->sum);
        if (ret < 0) {
            dict_release_iterator(iter);
            sdsfreesplitres(tokens, count);
            return ret;
        }

        val->sum = 0.0;

        ret = add_job_without_limit("SADD %s:mk:%s %s", coin, key, host);
        if (ret < 0) {
            dict_release_iterator(iter);
            sdsfreesplitres(tokens, count);
            return ret;
        }

        ret = add_job_without_limit("SADD monitor:keys %s:m:%s", coin, key);
        if (ret < 0) {
            dict_release_iterator(iter);
            sdsfreesplitres(tokens, count);
            return ret;
        }

        sdsfreesplitres(tokens, count);
    }
    dict_release_iterator(iter);

    return 0;
}

static int flush_data(time_t start)
{
    double begin = current_timestamp();
    ERR_RET(flush_share(start));
    ERR_RET(flush_monitor_int(start));
    ERR_RET(flush_monitor_float(start));
    double end = current_timestamp();
    log_info("flush data success, cost time: %f", end - begin);
    return 0;
}

static void on_timer(nw_timer *timer, void *privdata)
{
    time_t now = time(NULL);

    if (now - last_clear_worker >= WORKER_SAVE_TIME) {
        dict_clear(dict_worker);
        last_clear_worker = now;
    }

    if (now % 60 == 0 && flush_cost) {
        update_monitor_int("meta_flush_cost", settings.alert.host, "job", flush_cost);
        flush_cost = 0;
    }
    if (job->request_count > 0) {
        flush_cost += 1;
    }

    if (flush_error) {
        int ret = flush_data(last_flush - 60);
        if (ret < 0) {
            log_error("flush_data to redis fail: %d", ret);
            if ((now - flush_error_start) >= 60) {
                log_fatal("flush_data to redis fail last %ld seconds!", now - flush_error_start);
            }
        } else {
            flush_error = false;
        }
        return;
    }

    if (now - last_flush >= 60) {
        check_dict_recv(now);
        last_flush = now / 60 * 60;
        int ret = flush_data(last_flush - 60);
        if (ret < 0) {
            log_error("flush_data to redis fail: %d", ret);
            flush_error = true;
            flush_error_start = now;
        }
    }
}

int init_writer(void)
{
    ERR_RET(init_svr());
    ERR_RET(init_brother());
    ERR_RET(init_dict());
    ERR_RET(init_job());
    nw_timer_set(&timer, 1.0, true, on_timer, NULL);
    nw_timer_start(&timer);

    return 0;
}

void writer_flush(void)
{
    flush_data(time(NULL) / 60 * 60);
}

bool queue_clear(void)
{
    if (job->request_count == 0)
        return true;
    return false;
}

