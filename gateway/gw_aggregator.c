/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/02, create
 */

# include "gw_config.h"
# include "gw_writer.h"
# include "gw_aggregator.h"
# include "ut_misc.h"
# include "ut_pack.h"

# define MAX_PKG_BODY_SIZE  750

static nw_svr *svr;
static dict_t *dict_share;
static dict_t *dict_monitor_int;
static dict_t *dict_monitor_float;

static nw_timer timer;
static time_t last_flush;

struct dict_val_share {
    uint64_t num;
    uint64_t pow;
    double   goal;
};

struct dict_val_monitor_int {
    uint64_t sum;
};

struct dict_val_monitor_float {
    double sum;
};

static int dict_update_share(dict_t *dict, const sds key, uint64_t num, uint64_t pow, double goal)
{
    dict_entry *entry = dict_find(dict, key);
    if (entry == NULL) {
        struct dict_val_share val = { .num = num, .pow = pow, .goal = goal};
        dict_add(dict, key, &val);
        return 0;
    }
    struct dict_val_share *val = entry->val;
    val->num += num;
    val->pow += pow;
    val->goal += goal;
    return 0;
}

static int dict_update_monitor_int(dict_t *dict, const sds key, uint64_t num)
{
    dict_entry *entry = dict_find(dict, key);
    if (entry == NULL) {
        struct dict_val_monitor_int val = { .sum = num};
        dict_add(dict, key, &val);
        return 0;
    }
    struct dict_val_monitor_int *val = entry->val;
    val->sum += num;
    return 0;
}

static int dict_update_monitor_float(dict_t *dict, const sds key, double sum)
{
    dict_entry *entry = dict_find(dict, key);
    if (entry == NULL) {
        struct dict_val_monitor_float val = { .sum = sum };
        dict_add(dict, key, &val);
        return 0;
    }
    struct dict_val_monitor_float *val = entry->val;
    val->sum += sum;
    return 0;
}

static int send_pkg(uint32_t command, void *data, size_t size)
{
    char body[MAX_PKG_BODY_SIZE + 100];
    urandom(body, 32);
    memcpy(body + 32, data, size);

    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.command     = command;
    pkg.pkg_type    = RPC_PKG_TYPE_REQUEST;
    pkg.body        = body;
    pkg.body_size   = size + 32;

    return push_message(&pkg);
}

static int on_cmd_new_block(void *data, size_t size)
{
    return send_pkg(CMD_META_BLOCK, data, size);
}

static int on_cmd_new_share(void *data, size_t size)
{
    sds user, worker;
    uint64_t error, pow;
    double goal;
    ERR_RET(unpack_varstr(&data, &size, &user));
    ERR_RET(unpack_varstr(&data, &size, &worker));
    ERR_RET(unpack_varint_le(&data, &size, &error));
    ERR_RET(unpack_varint_le(&data, &size, &pow));
    ERR_RET(unpack_double_le(&data, &size, &goal));

    log_trace("pow:%ld, goal:%.16g", pow, goal);
    if (error != 0) {
        sds key = sdsempty();
        key = sdscat(key, "reject");
        dict_update_monitor_int(dict_monitor_int, key, 1);

        sdsclear(key);
        key = sdscatprintf(key, "reject_%d", (int)error);
        dict_update_monitor_int(dict_monitor_int, key, 1);

        sdsclear(key);
        key = sdscatprintf(key, "%s:reject", user);
        dict_update_share(dict_share, key, 1, 0, 0);

        sdsclear(key);
        key = sdscatprintf(key, "%s:%s:reject", user, worker);
        dict_update_share(dict_share, key, 1, 0, 0);

        sdsfree(key);
    } else {
        sds key = sdsempty();
        key = sdscat(key, "share");
        dict_update_monitor_int(dict_monitor_int, key, 1);

        sdsclear(key);
        key = sdscat(key, "pow");
        dict_update_monitor_int(dict_monitor_int, key, pow);

        sdsclear(key);
        key = sdscatprintf(key, "%s", user);
        dict_update_share(dict_share, key, 1, pow, goal);

        sdsclear(key);
        key = sdscatprintf(key, "%s:%s", user, worker);
        dict_update_share(dict_share, key, 1, pow, 0);

        sdsclear(key);
        key = sdscatprintf(key, "goal");
        dict_update_monitor_float(dict_monitor_float, key, goal);

        sdsfree(key);
    }

    sdsfree(user);
    sdsfree(worker);

    return 0;
}

static int on_cmd_new_event(void *data, size_t size)
{
    return send_pkg(CMD_META_EVENT, data, size);
}

static int on_cmd_key_value(void *data, size_t size)
{
    sds key;
    uint64_t value;
    ERR_RET(unpack_varstr(&data, &size, &key));
    ERR_RET(unpack_varint_le(&data, &size, &value));
    dict_update_monitor_int(dict_monitor_int, key, value);
    sdsfree(key);

    return 0;
}

static int decode_pkg(nw_ses *ses, void *data, size_t max)
{
    if (max < sizeof(struct aggreg_head)) {
        return 0;
    }
    struct aggreg_head head;
    memcpy(&head, data, sizeof(head));
    head.magic = le32toh(head.magic);
    head.pkg_size = le32toh(head.pkg_size);
    if (head.magic != AGGREG_MAGIC_NUM) {
        return -1;
    }
    if (max < head.pkg_size)
        return 0;
    return head.pkg_size;
}

static void on_recv_pkg(nw_ses *ses, void *data, size_t size)
{
    struct aggreg_head head;
    memcpy(&head, data, sizeof(head));
    head.command = le32toh(head.command);
    int ret = 0;
    switch (head.command) {
    case AGGREG_CMD_NEW_BLOCK:
        ret = on_cmd_new_block(data + sizeof(head), size - sizeof(head));
        break;
    case AGGREG_CMD_NEW_SHARE:
        ret = on_cmd_new_share(data + sizeof(head), size - sizeof(head));
        break;
    case AGGREG_CMD_NEW_EVENT:
        ret = on_cmd_new_event(data + sizeof(head), size - sizeof(head));
        break;
    case AGGREG_CMD_KEY_VALUE:
        ret = on_cmd_key_value(data + sizeof(head), size - sizeof(head));
        break;
    default:
        log_error("unkown aggregator command: %u", head.command);
        break;
    }
    
    if (ret < 0) {
        sds hex = hexdump(data, size);
        log_error("process cmd: %u fail: %d, data:\n%s", head.command, ret, hex);
        sdsfree(hex);
    }
}

static void on_new_connection(nw_ses *ses)
{
    log_info("new worker connected, current worker number: %u", svr->clt_count);
}

static void on_connection_close(nw_ses *ses)
{
    log_info("worker close, current worker number: %u", svr->clt_count - 1);
}

static void on_error_msg(nw_ses *ses, const char *msg)
{
    log_info("error: %s", msg);
}

static int init_svr(void)
{
    nw_svr_cfg cfg;
    nw_svr_bind bind;
    memset(&cfg, 0, sizeof(cfg));
    cfg.bind_count = 1;
    if (nw_sock_cfg_parse(GW_AGGREGATOR_BIND, &bind.addr, &bind.sock_type) < 0)
        return -__LINE__;
    cfg.bind_arr = &bind;
    cfg.max_pkg_size = 10240;

    nw_svr_type type;
    memset(&type, 0, sizeof(type));
    type.decode_pkg = decode_pkg;
    type.on_recv_pkg = on_recv_pkg;
    type.on_new_connection = on_new_connection;
    type.on_connection_close = on_connection_close;
    type.on_error_msg = on_error_msg;

    svr = nw_svr_create(&cfg, &type, NULL);
    if (svr == NULL)
        return -__LINE__;
    if (nw_svr_start(svr) < 0)
        return -__LINE__;

    return 0;
}

static uint32_t dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sdslen((sds)key));
}

static int dict_key_compare(const void *key1, const void *key2)
{
    return sdscmp((sds)key1, (sds)key2);
}

static void *dict_key_dup(const void *key)
{
    return sdsdup((sds)key);
}

static void dict_key_free(void *key)
{
    sdsfree((sds)key);
}

static void *dict_val_dup_share(const void *val)
{
    struct dict_val_share *new = malloc(sizeof(struct dict_val_share));
    memcpy(new, val, sizeof(struct dict_val_share));
    return new;
}

static void *dict_val_dup_monitor_int(const void *val)
{
    struct dict_val_monitor_int *new = malloc(sizeof(struct dict_val_monitor_int));
    memcpy(new, val, sizeof(struct dict_val_monitor_int));
    return new;
}

static void *dict_val_dup_monitor_float(const void *val)
{
    struct dict_val_monitor_float *new = malloc(sizeof(struct dict_val_monitor_float));
    memcpy(new, val, sizeof(struct dict_val_monitor_float));
    return new;
}

static void dict_val_free(void *val)
{
    free(val);
}

static int init_dict(void)
{
    dict_types type;
    memset(&type, 0, sizeof(type));
    type.hash_function  = dict_hash_func;
    type.key_compare    = dict_key_compare;
    type.key_dup        = dict_key_dup;
    type.key_destructor = dict_key_free;
    type.val_dup        = dict_val_dup_share;
    type.val_destructor = dict_val_free;

    dict_share = dict_create(&type, 64);
    if (dict_share == NULL)
        return -__LINE__;

    type.val_dup = dict_val_dup_monitor_int;
    dict_monitor_int = dict_create(&type, 64);
    if (dict_monitor_int == NULL)
        return -__LINE__;

    type.val_dup = dict_val_dup_monitor_float;
    dict_monitor_float = dict_create(&type, 64);
    if (dict_monitor_float == NULL)
        return -__LINE__;

    return 0;
}

static int flush_share(void)
{
    char body[2048];
    size_t body_size = 0;

    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(dict_share);
    while ((entry = dict_next(iter)) != NULL) {
        sds key = entry->key;
        struct dict_val_share *val = entry->val;
        if (val->num == 0)
            continue;

        log_debug("share key: %s num: %"PRId64" pow: %"PRId64" goal:%.16g", key, val->num, val->pow, val->goal);
        char buf[1024];
        void *p = buf;
        size_t left = sizeof(buf);
        pack_varstr(&p, &left, key, sdslen(key));
        pack_varstr(&p, &left, settings.alert.host, strlen(settings.alert.host));
        pack_varstr(&p, &left, settings.coin, strlen(settings.coin));
        pack_varint_le(&p, &left, val->num);
        pack_varint_le(&p, &left, val->pow);
        pack_double_le(&p, &left, val->goal);
        size_t size = sizeof(buf) - left;

        if (body_size + size > MAX_PKG_BODY_SIZE) {
            send_pkg(CMD_META_SHARE, body, body_size);
            body_size = 0;
        }
        memcpy(body + body_size, buf, size);
        body_size += size;
        if (body_size > MAX_PKG_BODY_SIZE) {
            send_pkg(CMD_META_SHARE, body, body_size);
            body_size = 0;
        }

        val->num = 0;
        val->pow = 0;
        val->goal = 0.0;
    }
    dict_release_iterator(iter);

    if (body_size) {
        send_pkg(CMD_META_SHARE, body, body_size);
    }

    return 0;
}

static int flush_monitor_int(void)
{
    char body[2048];
    size_t body_size = 0;

    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(dict_monitor_int);
    while ((entry = dict_next(iter)) != NULL) {
        sds key = entry->key;
        struct dict_val_monitor_int *val = entry->val;
        if (val->sum == 0)
            continue;
        log_debug("monitor key: %s sum: %"PRId64, key, val->sum);

        char buf[1024];
        void *p = buf;
        size_t left = sizeof(buf);
        pack_varstr(&p, &left, key, sdslen(key));
        pack_varstr(&p, &left, settings.alert.host, strlen(settings.alert.host));
        pack_varstr(&p, &left, settings.coin, strlen(settings.coin));
        pack_varint_le(&p, &left, val->sum);
        size_t size = sizeof(buf) - left;

        if (body_size + size > MAX_PKG_BODY_SIZE) {
            send_pkg(CMD_META_MONITOR_INT, body, body_size);
            body_size = 0;
        }
        memcpy(body + body_size, buf, size);
        body_size += size;
        if (body_size > MAX_PKG_BODY_SIZE) {
            send_pkg(CMD_META_MONITOR_INT, body, body_size);
            body_size = 0;
        }

        val->sum = 0;
    }
    dict_release_iterator(iter);

    if (body_size) {
        send_pkg(CMD_META_MONITOR_INT, body, body_size);
    }

    return 0;
}

static int flush_monitor_float(void)
{
    char body[2048];
    size_t body_size = 0;

    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(dict_monitor_float);
    while ((entry = dict_next(iter)) != NULL) {
        sds key = entry->key;
        struct dict_val_monitor_float *val = entry->val;
        if (fabs(val->sum) <= 1e-15)
            continue;
        log_debug("monitor key: %s sum: %.16g", key, val->sum);

        char buf[1024];
        void *p = buf;
        size_t left = sizeof(buf);
        pack_varstr(&p, &left, key, sdslen(key));
        pack_varstr(&p, &left, settings.alert.host, strlen(settings.alert.host));
        pack_varstr(&p, &left, settings.coin, strlen(settings.coin));
        pack_double_le(&p, &left, val->sum);
        size_t size = sizeof(buf) - left;

        if (body_size + size > MAX_PKG_BODY_SIZE) {
            send_pkg(CMD_META_MONITOR_FLOAT, body, body_size);
            body_size = 0;
        }
        memcpy(body + body_size, buf, size);
        body_size += size;
        if (body_size > MAX_PKG_BODY_SIZE) {
            send_pkg(CMD_META_MONITOR_FLOAT, body, body_size);
            body_size = 0;
        }

        val->sum = 0.0;
    }
    dict_release_iterator(iter);

    if (body_size) {
        send_pkg(CMD_META_MONITOR_FLOAT, body, body_size);
    }

    return 0;
}

static int flush_data(void)
{
    double begin = current_timestamp();
    ERR_RET(flush_share());
    ERR_RET(flush_monitor_int());
    ERR_RET(flush_monitor_float());

    double end = current_timestamp();
    log_info("flush data success, cost time: %f", end - begin);

    return 0;
}

static void on_timer(nw_timer *timer, void *privdata)
{
    time_t now = time(NULL);
    if ((now % 60 >= 30) && (now - last_flush) >= 60) {
        last_flush = now / 60 * 60 + 30;
        int ret = flush_data();
        if (ret < 0) {
            log_error("flush_data fail: %d", ret);
        }
    }
}

int init_aggregator(void)
{
    ERR_RET(init_svr());
    ERR_RET(init_dict());

    nw_timer_set(&timer, 1.0, true, on_timer, NULL);
    nw_timer_start(&timer);

    return 0;
}

void aggregator_flush(void)
{
    flush_data();
}

