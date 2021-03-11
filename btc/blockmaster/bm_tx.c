/*
 * Description: 
 *     History: yang@haipo.me, 2016/10/22, create
 */

# include "bm_config.h"
# include "bm_tx.h"
# include "nw_job.h"
# include "ut_dict.h"

static nw_job *job;
static dict_t *tx_dict;
static coin_rpc *coin;
static nw_timer timer;

struct tx_value {
    sds hash;
    sds data;
    double update;
};

static uint32_t tx_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, TX_KEY_SIZE);
}
static int tx_dict_key_compare(const void *key1, const void *key2)
{
    return memcmp(key1, key2, TX_KEY_SIZE);
}
static void *tx_dict_key_dup(const void *key)
{
    void *p = malloc(TX_KEY_SIZE);
    memcpy(p, key, TX_KEY_SIZE);
    return p;
}
static void tx_dict_key_free(void *key)
{
    free(key);
}
static void tx_dict_val_free(void *val)
{
    struct tx_value *obj = val;
    if (obj->hash) {
        sdsfree(obj->hash);
    }
    if (obj->data) {
        sdsfree(obj->data);
    }
    free(val);
}

static void getrawtransaction(const char *hash)
{
    json_t *params = json_array();
    json_array_append_new(params, json_string(hash));

    json_t *message = json_object();
    json_object_set_new(message, "timeout", json_real(1.0));
    json_object_set_new(message, "method", json_string("getrawtransaction"));
    json_object_set_new(message, "params", params);

    int ret = nw_job_add(job, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail: %d", ret);
    }
}

void update_tx(void *hash, void *data, size_t data_size)
{
    double timestamp = current_timestamp();
    dict_entry *entry = dict_find(tx_dict, hash);
    if (entry) {
        struct tx_value *obj = entry->val;
        obj->update = timestamp;
        if (obj->data == NULL && data) {
            obj->data = sdsnewlen(data, data_size);
        }
    } else {
        struct tx_value *obj = malloc(sizeof(struct tx_value));
        memset(obj, 0, sizeof(struct tx_value));
        obj->hash = bin2hex(hash, 32);
        if (data) {
            obj->data = sdsnewlen(data, data_size);
        } else {
            getrawtransaction(obj->hash);
        }
        obj->update = timestamp;
        dict_add(tx_dict, hash, obj);
    }
}

static int update_mempool(json_t *r)
{
    size_t index;
    json_t *value;
    json_array_foreach(r, index, value) {
        sds bin = hex2bin(json_string_value(value));
        update_tx(bin, NULL, 0);
        sdsfree(bin);
    }

    return 0;
}

static int delete_expire(void)
{
    double now = current_timestamp();
    dict_iterator *iter = dict_get_iterator(tx_dict);
    dict_entry *entry;
    while ((entry = dict_next(iter)) != NULL) {
        struct tx_value *obj = entry->val;
        if (now - obj->update > 600) {
            dict_delete(tx_dict, entry->key);
        }
    }
    dict_release_iterator(iter);

    return 0;
}

static void *on_job_init(void)
{
    return coin_rpc_create(&settings.coin);
}
static void on_job(nw_job_entry *entry, void *privdata)
{
    double start = current_timestamp();
    json_t *message = entry->request;
    entry->reply = coin_rpc_cmd(privdata,
            json_number_value(json_object_get(message, "timeout")),
            json_string_value(json_object_get(message, "method")),
            json_object_get(message, "params"));
    double end = current_timestamp();
    log_trace("rpc command: %s cost: %f", json_string_value(json_object_get(message, "method")), end - start);
}

static void on_job_finish(nw_job_entry *entry)
{
    json_t *message = entry->request;
    const char *method = json_string_value(json_object_get(message, "method"));
    json_t *reply = entry->reply;
    if (reply == NULL) {
        log_error("rpc %s fail", method);
        return;
    }

    if (strcmp(method, "getrawmempool") == 0) {
        int ret;
        ret = update_mempool(reply);
        if (ret < 0) {
            log_error("update_mempool fail: %d", ret);
        }
        ret = delete_expire();
        if (ret < 0) {
            log_error("delete_expire fail: %d", ret);
        }
    } else if (strcmp(method, "getrawtransaction") == 0) {
        sds data = hex2bin(json_string_value(reply));
        if (data) {
            char hash[32];
            sha256d(data, sdslen(data), hash);
            reverse_mem(hash, sizeof(hash));
            update_tx(hash, data, sdslen(data));
            sdsfree(data);
        }
    }
}

static void on_job_cleanup(nw_job_entry *entry)
{
    if (entry->request)
        json_decref(entry->request);
    if (entry->reply)
        json_decref(entry->reply);
}
static void on_job_release(void *privdata)
{
    coin_rpc_release(privdata);
}

static void on_timer(nw_timer *timer, void *privdata)
{
    json_t *message = json_object();
    json_object_set_new(message, "timeout", json_real(10.0));
    json_object_set_new(message, "method", json_string("getrawmempool"));
    json_object_set_new(message, "params", json_array());

    int ret = nw_job_add(job, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail: %d", ret);
    }
}

int init_tx(void)
{
    dict_types type_tx;
    memset(&type_tx, 0, sizeof(type_tx));

    type_tx.hash_function = tx_dict_hash_func;
    type_tx.key_compare = tx_dict_key_compare;
    type_tx.key_dup = tx_dict_key_dup;
    type_tx.key_destructor = tx_dict_key_free;
    type_tx.val_destructor = tx_dict_val_free;

    tx_dict = dict_create(&type_tx, 1024);
    if (tx_dict == NULL)
        return -__LINE__;

    coin = coin_rpc_create(&settings.coin);
    if (coin == NULL)
        return -__LINE__;

    nw_job_type type_job;
    memset(&type_job, 0, sizeof(type_job));
    type_job.on_init = on_job_init;
    type_job.on_job = on_job;
    type_job.on_finish = on_job_finish;
    type_job.on_cleanup = on_job_cleanup;
    type_job.on_release = on_job_release;

    job = nw_job_create(&type_job, 2);
    if (job == NULL)
        return -__LINE__;

    nw_timer_set(&timer, settings.mempool_timeout, true, on_timer, NULL);
    nw_timer_start(&timer);

    return 0;
}

sds get_tx_info(void)
{
    sds reply = sdsempty();
    reply = sdscatprintf(reply, "%d\n", tx_dict->used);
    return reply;
}

sds get_tx_data(void *key)
{
    dict_entry *entry = dict_find(tx_dict, key);
    if (!entry)
        return NULL;
    struct tx_value *obj = entry->val;
    if (obj->data) {
        return obj->data;
    }

    return NULL;
}

int decode_block(void *block, size_t block_size, char *block_head, sds *coinbase_tx, uint32_t *tx_count, sds *tx_info)
{
    if (block_size < 80)
        return -__LINE__;
    memcpy(block_head, block, 80);

    sdsclear(*coinbase_tx);
    sdsclear(*tx_info);
    *tx_count = 0;

    void *p = block + 80;
    size_t left = block_size - 80;

    uint64_t count;
    ERR_RET_LN(unpack_varint_le(&p, &left, &count));
    for (size_t i = 0; i < count; ++i) {
        void *tx = p;
        size_t pos = left;
        bool is_segwit_tx = false;

        uint32_t tx_version;
        ERR_RET_LN(unpack_uint32_le(&p, &left, &tx_version));
        if (*(uint8_t *)p == 0) {
            is_segwit_tx = true;
            uint8_t marker, flag;
            ERR_RET_LN(unpack_char(&p, &left, &marker));
            ERR_RET_LN(unpack_char(&p, &left, &flag));
        }

        uint64_t tx_in_count;
        ERR_RET_LN(unpack_varint_le(&p, &left, &tx_in_count));
        for (size_t i = 0; i < tx_in_count; ++i) {
            if (left < 36)
                return -__LINE__;
            left -= 36;
            p += 36;
            uint64_t script_size;
            ERR_RET_LN(unpack_varint_le(&p, &left, &script_size));
            if (left < script_size)
                return -__LINE__;
            left -= script_size;
            p += script_size;
            uint32_t sequence;
            ERR_RET_LN(unpack_uint32_le(&p, &left, &sequence));
        }
        uint64_t tx_out_count;
        ERR_RET_LN(unpack_varint_le(&p, &left, &tx_out_count));
        for (size_t i = 0; i < tx_out_count; ++i) {
            uint64_t value;
            ERR_RET_LN(unpack_uint64_le(&p, &left, &value));
            uint64_t script_size;
            ERR_RET_LN(unpack_varint_le(&p, &left, &script_size));
            if (left < script_size)
                return -__LINE__;
            left -= script_size;
            p += script_size;
        }

        if (is_segwit_tx) {
            for (size_t i = 0; i < tx_in_count; ++i) {
                uint64_t witness_count;
                ERR_RET_LN(unpack_varint_le(&p, &left, &witness_count));
                for (size_t j = 0; j < witness_count; ++j) {
                    uint64_t witness_size;
                    ERR_RET_LN(unpack_varint_le(&p, &left, &witness_size));
                    if (left < witness_size)
                        return -__LINE__;
                    left -= witness_size;
                    p += witness_size;
                }
            }
        }

        uint32_t lock_time;
        ERR_RET_LN(unpack_uint32_le(&p, &left, &lock_time));

        size_t tx_size = pos - left;
        if (i == 0) {
            *coinbase_tx = sdscatlen(*coinbase_tx, tx, tx_size);
        } else {
            char hash[32];
            sha256d(tx, tx_size, hash);
            reverse_mem(hash, sizeof(hash));
            update_tx(hash, tx, tx_size);
            *tx_info = sdscatlen(*tx_info, hash, TX_KEY_SIZE);
            *tx_count += 1;
        }
    }

    return 0;
}

