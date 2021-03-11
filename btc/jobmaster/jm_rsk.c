# include "nw_job.h"
# include "jm_rsk.h"
# include "jm_job.h"
# include "jm_monitor.h"

static nw_job *job;
static nw_timer timer;

static int req_getblockcount(void)
{
    json_t *message = json_object();
    json_object_set_new(message, "timeout", json_real(10.0));
    json_object_set_new(message, "method", json_string("eth_blockNumber"));
    json_object_set_new(message, "params", json_array());

    int ret = nw_job_add(job, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail: %d", ret);
        return -__LINE__;
    }
    return 0;
}

static int req_getrskwork(bool update)
{
    json_t *message = json_object();
    json_object_set_new(message, "timeout", json_real(10.0));
    json_object_set_new(message, "update", json_boolean(update));
    json_object_set_new(message, "method", json_string("mnr_getWork"));
    json_object_set_new(message, "params", json_array());

    int ret = nw_job_add(job, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail %d", ret);
        return -__LINE__;
    }

    return 0;
}

static json_t *rpc_getrskwork(coin_rpc *coin)
{
    double start = current_timestamp();
    json_t *r = coin_rpc_cmd(coin, 2.0, "mnr_getWork", NULL);
    double end = current_timestamp();
    log_trace("rsk rpc_getwork cost time: %f", end - start);

    if (r == NULL) {
        log_error("rsk rpc getwork fail");
        return NULL;
    }
    return r;
}

static int rpc_getblockcountbyhash(coin_rpc *coin, const char *hash)
{
    double start = current_timestamp();
    json_t *params = json_array();
    json_array_append_new(params, json_string(hash));
    json_array_append_new(params, json_boolean(false));
    json_t *r = coin_rpc_cmd(coin, 2.0, "eth_getBlockByHash", params);
    double end = current_timestamp();
    log_trace("rsk blockcountbyhash cost time: %f, hash: %s", end - start, hash);
    json_decref(params);

    json_t *height_obj = json_object_get(r, "number");
    if (r == NULL || height_obj == NULL) {
        log_error("rsk rpc getblockbyhash fail, hash: %s", hash);
        if (r) {
            json_decref(r);
        }
        return -__LINE__;
    }

    int height = strtoul(json_string_value(height_obj), NULL, 16);
    json_decref(r);

    return height;
}

static void on_job(nw_job_entry *entry, void *privdata)
{
    json_t *message = entry->request;
    double start = current_timestamp();
    entry->reply = coin_rpc_cmd(rsk_info->coin,
            json_number_value(json_object_get(message, "timeout")),
            json_string_value(json_object_get(message, "method")),
            json_object_get(message, "params"));

    const char *method = json_string_value(json_object_get(message, "method"));
    if (entry->reply && strcmp(method, "mnr_getWork") == 0) {
        json_t *pre_hash_obj = json_object_get(entry->reply, "parentBlockHash");
        int mine_height = rpc_getblockcountbyhash(rsk_info->coin, json_string_value(pre_hash_obj)) + 1;
        json_object_set_new(entry->reply, "mine_height", json_integer(mine_height));
    }
    double end = current_timestamp();
    log_trace("rsk rpc command: %s cost: %f", method, end - start);
}

static bool rsk_job_update()
{
    static time_t job_update_last = 0;
    time_t now = time(NULL);

    if (job_update_last == 0 || now - job_update_last >= settings.rsk_job_interval) {
        job_update_last = now;
        return true;    
    }
    return false;
}

static void on_finish(nw_job_entry *entry)
{
    json_t *message = entry->request;
    const char *method = json_string_value(json_object_get(message, "method"));
    json_t *reply = entry->reply;
    if (reply == NULL) {
        log_fatal("rsk rpc %s fail", method);
        return;
    }

    if (strcmp(method, "eth_blockNumber") == 0) {
        int height = strtoul(json_string_value(reply), NULL, 16);
        if (height > rsk_info->height) {
            log_info("rsk height update to %d", height);
            rsk_info->height = height;
            req_getrskwork(true);
        }
    } else if (strcmp(method, "mnr_getWork") == 0) {
        if (rsk_info->block)
            json_decref(rsk_info->block);
        json_incref(reply);
        rsk_info->block = reply;
        rsk_info->mine_height = json_integer_value(json_object_get(rsk_info->block, "mine_height"));
        log_info("rsk get new job, mine_height: %d", rsk_info->mine_height);

        if (rsk_job_update()) {
            log_info("rsk job update");
            rsk_info->update_time = time(NULL);
            int ret = on_rsk_update();
            if (ret < 0) {
                log_error("on_rsk_update fail: %d", ret);
            }
        }
    } else if (strcmp(method, "mnr_submitBitcoinBlockPartialMerkle") == 0) {
        json_t *params = json_object_get(message, "params");
        const char *rsk_hash = json_string_value(json_array_get(params, 0));
        json_t *error = json_object_get(reply, "error");
        if (error) {
            inc_submit_aux_error();
            const char *message = json_string_value(json_object_get(error, "message"));
            int code = json_integer_value(json_object_get(error, "code"));
            log_fatal("submit rsk block fail, hash: %s, code: %d, message: %s", rsk_hash, code, message);
        } else {
            inc_submit_aux_success();
            const char *blockImportedResult = json_string_value(json_object_get(reply, "blockImportedResult"));
            const char *blockHash = json_string_value(json_object_get(reply, "blockHash"));
            const char *blockIncludedHeight = json_string_value(json_object_get(reply, "blockIncludedHeight"));
            log_info("submit rsk block success, hash: %s, blockImportedResult: %s, blockHash: %s, blockIncludedHeight: %s", 
                    rsk_hash, blockImportedResult, blockHash, blockIncludedHeight);
        }
    } else {
        log_error("unknown method: %s", method);
    }
}

static void on_cleanup(nw_job_entry *entry)
{    
    if (entry->request)
        json_decref(entry->request);
    if (entry->reply)
        json_decref(entry->reply);
}

static void on_timer(nw_timer *timer, void *privdata)
{
    req_getblockcount();
    if (time(NULL) - rsk_info->update_time >= settings.aux_job_timeout) {
        req_getrskwork(false);
    }
}

int init_rsk()
{
    if (!settings.rsk_coin)
        return 0;

    rsk_info = (rsk_coin_info *)malloc(sizeof(rsk_coin_info));
    memset(rsk_info, 0, sizeof(rsk_coin_info));
    rsk_info->coin = coin_rpc_create(settings.rsk_coin);
    if (!rsk_info->coin)
        return -__LINE__;

    rsk_info->rsk_name = sdsnew(settings.rsk_coin->name);
    rsk_info->block = rpc_getrskwork(rsk_info->coin);
    if (!rsk_info->block)
        return -__LINE__;

    json_t *pre_hash_obj = json_object_get(rsk_info->block, "parentBlockHash");
    rsk_info->mine_height = rpc_getblockcountbyhash(rsk_info->coin, json_string_value(pre_hash_obj)) + 1;
    if (rsk_info->mine_height < 0)
        return -__LINE__;

    nw_job_type type;
    memset(&type, 0, sizeof(type));
    type.on_job = on_job;
    type.on_finish = on_finish;
    type.on_cleanup = on_cleanup;
    job = nw_job_create(&type, 2);
    if (job == NULL)
        return -__LINE__;

    nw_timer_set(&timer, 1, true, on_timer, NULL);
    nw_timer_start(&timer);
    return 0;
}

int submit_rsk_block(const char *block_hash, const char *block_header, const char *coinbase, const char *merkle_hashes, int blocktxn_count)
{
    json_t *message = json_object();
    json_object_set_new(message, "timeout", json_real(10.0));
    json_object_set_new(message, "method", json_string("mnr_submitBitcoinBlockPartialMerkle"));

    json_t *params = json_array();
    json_array_append_new(params, json_string(block_hash));
    json_array_append_new(params, json_string(block_header));
    json_array_append_new(params, json_string(coinbase));
    json_array_append_new(params, json_string(merkle_hashes));
    json_array_append_new(params, json_integer(blocktxn_count));

    json_object_set_new(message, "params", params);
    int ret = nw_job_add(job, 0, message);
    if (ret < 0) {
        json_decref(message);
        log_fatal("nw_job_add fail: %d", ret);
        return -__LINE__;
    }

    return 0;
}

