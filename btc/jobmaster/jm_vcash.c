/*
 * Description: job master server
 *     History: yangxiaoqiang@viabtc.com, 2020/06/10, create
 */

# include "nw_job.h"
# include "jm_vcash.h"
# include "jm_job.h"
# include "jm_monitor.h"

static nw_job *job;
static nw_timer timer;

struct rpc_reply
{
    long    http_code;
    json_t  *repsonse; 
};

static int req_getkwork()
{
    json_t *message = json_object();
    json_object_set_new(message, "timeout", json_real(10.0));
    json_object_set_new(message, "method", json_string("GET"));
    json_object_set_new(message, "url", json_string("/v1/pool/getauxblock"));

    int ret = nw_job_add(job, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail %d", ret);
        return -__LINE__;
    }

    return 0;
}

static json_t *rpc_getwork(coin_rpc *coin)
{
    double start = current_timestamp();
    long http_code = 0;
    json_t *r = coin_get_json(coin, 30, "/v1/pool/getauxblock", &http_code);
    double end = current_timestamp();
    log_trace("name: %s getauxblock cost time: %f", coin->name, end - start);

    if (http_code != 200 || r == NULL) {
        log_error("vcash rpc getauxblock fail");
        return NULL;
    }
    return r;
}

static void on_job(nw_job_entry *entry, void *privdata)
{
    struct rpc_reply *reply = malloc(sizeof(struct rpc_reply));
    memset(reply, 0, sizeof(struct rpc_reply));
    double start = current_timestamp();
    json_t *message = entry->request;
    const char *method = json_string_value(json_object_get(message, "method"));
    const char *url = json_string_value(json_object_get(message, "url"));
    const double timeout = json_number_value(json_object_get(message, "timeout"));
    if (strcmp(method, "GET") == 0) {
        long http_code = 0;
        reply->repsonse = coin_get_json(vcash_info->coin, timeout, url, &http_code);
        reply->http_code = http_code;
        entry->reply = reply;
    } else if (strcmp(method, "POST") == 0) {
        const char *params = json_string_value(json_object_get(message, "params"));
        long http_code = 0;
        reply->repsonse = coin_post(vcash_info->coin, timeout, url, params, &http_code);
        reply->http_code = http_code;
        entry->reply = reply;
    }
    double end = current_timestamp();
    log_trace("rpc command: %s cost: %f", url, end - start);
}

static uint64_t on_blockheight_update(json_t *reply)
{
    int64_t height = json_integer_value(json_object_get(reply, "height"));
    log_trace("vcash height %"PRId64, height);

    if (height > vcash_info->height) {
        log_info("vcash height update %"PRId64, height);
        if (vcash_info->block)
            json_decref(vcash_info->block);
        json_incref(reply);
        vcash_info->block = reply;
        vcash_info->height = height;
        vcash_info->update_time = time(NULL);
        int ret = on_vcash_update();
        if (ret < 0) {
            log_error("on_vcash_update fail: %d", ret);
        }
    } 
    return height;
}

static void on_finish(nw_job_entry *entry)
{
    json_t *message = entry->request;
    const char *url = json_string_value(json_object_get(message, "url"));
    struct rpc_reply *reply = entry->reply;
    if (reply->http_code != 200) {
        if (strcmp(url, "/v1/pool/submitauxblock") == 0) {
            log_fatal("submitauxblock fail: %ld", reply->http_code);
        } else {
            log_error("rpc %s fail", url);
        }
        return;
    }

    if (strcmp(url, "/v1/pool/getauxblock") == 0) {
        uint64_t blockcount = on_blockheight_update(reply->repsonse);
        log_trace("blockcount:%"PRId64, blockcount);
        if (blockcount == 0) {
            log_error("count_update fail: %"PRId64, blockcount);
        }
    } else if (strcmp(url, "/v1/pool/submitauxblock") == 0) {
        log_info("submitauxblock return: %ld", reply->http_code);
    }
    return;
}

static void on_cleanup(nw_job_entry *entry)
{    
    if (entry->request)
        json_decref(entry->request);
    if (entry->reply) {
        struct rpc_reply *reply = entry->reply;
        if (reply->repsonse)
            json_decref(reply->repsonse);
        free(reply);
    }
}

static void on_timer(nw_timer *timer, void *privdata)
{
    req_getkwork();
}

int init_vcash()
{
    if (!settings.vcash_coin)
        return 0;

    vcash_info = (vcash_coin_info *)malloc(sizeof(vcash_coin_info));
    memset(vcash_info, 0, sizeof(vcash_coin_info));
    vcash_info->coin = coin_rpc_create(settings.vcash_coin);
    if (!vcash_info->coin)
        return -__LINE__;

    vcash_info->vcash_name = sdsnew(settings.vcash_coin->name);
    vcash_info->block = rpc_getwork(vcash_info->coin);
    if (!vcash_info->block)
        return -__LINE__;

    nw_job_type type;
    memset(&type, 0, sizeof(type));
    type.on_job = on_job;
    type.on_finish = on_finish;
    type.on_cleanup = on_cleanup;
    job = nw_job_create(&type, 2);
    if (job == NULL)
        return -__LINE__;

    nw_timer_set(&timer, 0.5, true, on_timer, NULL);
    nw_timer_start(&timer);
    return 0;
}

int submit_vcash_block(const char *block_hash, const char *block_header, const char *coinbase, const char *merkle_hashes)
{
    json_t *message = json_object();
    json_object_set_new(message, "timeout", json_real(10.0));
    json_object_set_new(message, "method", json_string("POST"));
    json_object_set_new(message, "url", json_string("/v1/pool/submitauxblock"));

    json_t *params = json_object();
    json_object_set(params, "header_hash", json_string(block_hash));
    json_object_set(params, "btc_header", json_string(block_header));
    json_object_set(params, "btc_coinbase", json_string(coinbase));
    json_object_set(params, "btc_merkle_branch", json_string(merkle_hashes));

    char *params_str = json_dumps(params, 0);
    if (params_str == NULL) {
        log_error("json_dumps params fail");
        json_decref(message);
        json_decref(params);
        return -__LINE__;
    }
    log_info("submit vcash: %s", params_str);
    json_object_set_new(message, "params", json_string(params_str));
    free(params_str);
    json_decref(params);

    int ret = nw_job_add(job, 0, message);
    if (ret < 0) {
        json_decref(message);
        log_fatal("nw_job_add fail: %d", ret);
        return -__LINE__;
    }

    return 0;
}

