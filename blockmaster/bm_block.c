/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/18, create
 */

# include "bm_config.h"
# include "bm_block.h"
# include "bm_master.h"
# include "bm_peer.h"
# include "bm_tx.h"
# include "nw_job.h"
# include "ut_crc32.h"

static int height;
static int out_height;
static nw_job *job;
static coin_rpc *coin;
static nw_timer timer;
static dict_t *block_dict;

static void check_new_block(void)
{
    json_t *message = json_object();
    json_object_set_new(message, "timeout", json_real(1.0));
    json_object_set_new(message, "method", json_string("getblockcount"));
    json_object_set_new(message, "params", json_array());

    int ret = nw_job_add(job, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail: %d", ret);
        return;
    }
}

static void on_timer(nw_timer *timer, void *privdata)
{
    check_new_block();
}

static uint32_t sds_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sdslen((sds)key));
}
static int sds_dict_key_compare(const void *key1, const void *key2)
{
    return sdscmp((sds)key1, (sds)key2);
}
static void sds_dict_key_free(void *key)
{
    sdsfree(key);
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

    if (strcmp(method, "submitblock") == 0) {
        if (json_is_null(reply)) {
            log_info("submitblock success");
        } else {
            const char *error = json_string_value(reply);
            if (error == NULL)
                error = "null";
            log_error("submitblock fail: %s", error);
        }
    } else if (strcmp(method, "getblockcount") == 0) {
        int blockcount = json_integer_value(reply);
        if (blockcount > height) {
            height = blockcount;
            log_info("height update to: %d", height);
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

int init_block(void)
{
    coin = coin_rpc_create(&settings.coin);
    if (coin == NULL)
        return -__LINE__;

    nw_timer_set(&timer, 1.0, true, on_timer, NULL);
    nw_timer_start(&timer);

    dict_types type_block;
    memset(&type_block, 0, sizeof(type_block));
    type_block.hash_function = sds_dict_hash_func;
    type_block.key_compare = sds_dict_key_compare;
    type_block.key_destructor = sds_dict_key_free;

    block_dict = dict_create(&type_block, 1024);
    if (block_dict == NULL)
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

    return 0;
}

int on_blocknotify(void)
{
    check_new_block();
    return 0;
}

static void update_block_dict(const char *block_hash)
{
    sds key = sdsnew(block_hash);
    if (dict_add(block_dict, key, NULL) < 0) {
        sdsfree(key);
    }
}

static int submitblock(const char *block_hash, const char *block)
{
    json_t *params = json_array();
    json_array_append_new(params, json_string(block));

    json_t *message = json_object();
    json_object_set_new(message, "timeout", json_real(10.0));
    json_object_set_new(message, "method", json_string("submitblock"));
    json_object_set_new(message, "params", params);

    log_info("submitblock: %s", block_hash);
    int ret = nw_job_add(job, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail: %d", ret);
        return -__LINE__;
    }

    return 0;
}

static int broadcast_peer_block(void *data, size_t size, uint32_t cmd)
{
    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.command = cmd;
    pkg.pkg_type = RPC_PKG_TYPE_PUSH;
    pkg.body = data;
    pkg.body_size = size;

    log_info("broadcast_peer_msg");
    broadcast_peer_msg(&pkg);

    return 0;
}

static int broadcast_thin_block(void *data, size_t size, uint32_t cmd)
{
    char block_hash[32];
    sha256d(data, 80, block_hash);
    reverse_mem(block_hash, sizeof(block_hash));

    char block_head[80];
    uint32_t tx_count = 0;
    sds coinbase_tx = sdsempty();
    sds tx_info = sdsempty();
    int ret = decode_block(data, size, block_head, &coinbase_tx, &tx_count, &tx_info);
    if (ret < 0) {
        log_error("decode_block fail: %d", ret);
        return -__LINE__;
    }

    char buf[1000 * 1000];
    void *p = buf;
    size_t left = sizeof(buf);
    ERR_RET_LN(pack_buf(&p, &left, block_hash, sizeof(block_hash)));
    ERR_RET_LN(pack_buf(&p, &left, block_head, sizeof(block_head)));
    ERR_RET_LN(pack_varstr(&p, &left, coinbase_tx, sdslen(coinbase_tx)));
    ERR_RET_LN(pack_uint32_le(&p, &left, tx_count));
    ERR_RET_LN(pack_buf(&p, &left, tx_info, sdslen(tx_info)));

    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.command = cmd;
    pkg.pkg_type = RPC_PKG_TYPE_PUSH;
    pkg.body = buf;
    pkg.body_size = sizeof(buf) - left;

    log_info("broadcast_master_msg");
    broadcast_master_msg(&pkg);
    sdsfree(coinbase_tx);
    sdsfree(tx_info);

    return 0;
}

int on_submit_block(void *data, size_t size)
{
    if (size <= 80) {
        log_error("invalid block size: %zu", size);
        return -__LINE__;
    }

    int ret;
    ret = broadcast_peer_block(data, size, CMD_SUBMIT_BLOCK);
    if (ret < 0) {
        log_error("broadcast_peer_block fail: %d", ret);
    }
    ret = broadcast_thin_block(data, size, CMD_THIN_BLOCK_SUBMIT);
    if (ret < 0) {
        log_error("broadcast_thin_block fail: %d", ret);
    }

    char hash[32];
    sha256d(data, 80, hash);
    reverse_mem(hash, sizeof(hash));
    sds block_hash = bin2hex(hash, sizeof(hash));
    log_info("recv submit block hash: %s, size: %zu, crc32: %u", block_hash, size, generate_crc32c(data, size));
    sds block = bin2hex(data, size);
    update_block_dict(block_hash);
    submitblock(block_hash, block);
    sdsfree(block_hash);
    sdsfree(block);

    return 0;
}

static int get_height_from_coinbase(void *p, size_t left)
{
    uint32_t tx_version;
    ERR_RET_LN(unpack_uint32_le(&p, &left, &tx_version));
    bool is_segwit_tx = false;
    if (*(uint8_t *)p == 0) {
        is_segwit_tx = true;
        uint8_t marker, flag;
        ERR_RET_LN(unpack_char(&p, &left, &marker));
        ERR_RET_LN(unpack_char(&p, &left, &flag));
    }

    void *coinbase = NULL;
    size_t coinbase_size = 0;

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
        if (script_size && i == 0) {
            coinbase = p;
            coinbase_size = script_size;
        }
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
                if (coinbase == NULL && i == 0) {
                    coinbase = p;
                    coinbase_size = witness_size;
                }
                left -= witness_size;
                p += witness_size;
            }
        }
    }

    if (!coinbase) {
        return -__LINE__;
    }

    int64_t height = 0;
    ERR_RET_LN(unpack_oppushint_le(&coinbase, &coinbase_size, &height));
    return height;
}

static int get_block_height(void *data, size_t size)
{
    void *p = data + 80;
    size_t left = size - 80;
    uint64_t tx_count;
    ERR_RET_LN(unpack_varint_le(&p, &left, &tx_count));
    return get_height_from_coinbase(p, left);
}

int on_update_block(void *data, size_t size)
{
    if (size <= 80)
        return -__LINE__;
    int ret = get_block_height(data, size);
    if (ret < 0)
        return ret;
    if (ret <= height)
        return 0;

    out_height = ret;
    ret = broadcast_peer_block(data, size, CMD_UPDATE_BLOCK);
    if (ret < 0) {
        log_error("broadcast_peer_block fail: %d", ret);
    }
    ret = broadcast_thin_block(data, size, CMD_THIN_BLOCK_UPDATE);
    if (ret < 0) {
        log_error("broadcast_thin_block fail: %d", ret);
    }

    char hash[32];
    sha256d(data, 80, hash);
    reverse_mem(hash, 32);
    sds block_hash = bin2hex(hash, sizeof(hash));
    log_info("recv update block hash: %s, size: %zu, crc32: %u", block_hash, size, generate_crc32c(data, size));
    sds block = bin2hex(data, size);
    update_block_dict(block_hash);
    submitblock(block_hash, block);
    sdsfree(block_hash);
    sdsfree(block);

    return 1;
}

bool is_block_exist(char *block_hash)
{
    sds key = bin2hex(block_hash, 32);
    dict_entry *entry = dict_find(block_dict, key);
    if (entry) {
        sdsfree(key);
        return true;
    }
    log_debug("block %s not exist", key);
    sdsfree(key);
    return false;
}

int get_outer_height(void)
{
    return out_height;
}

int get_self_height(void)
{
    return height;
}

