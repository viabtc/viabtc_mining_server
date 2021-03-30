/*
 * Description: 
 *     History: yang@haipo.me, 2016/07/20, create
 */

# include "nw_job.h"
# include "jm_aux.h"
# include "jm_job.h"
# include "jm_rsk.h"

static nw_job *job;
static nw_timer timer;
static int32_t merkle_size;

static int cal_merkle_index(int chain_id, int nonce, int size)
{
    unsigned int rand = nonce;
    rand = rand * 1103515245 + 12345;
    rand += chain_id;
    rand = rand * 1103515245 + 12345;
    return rand % size;
}

static int cal_merkle_size(int chain_len)
{
    int32_t size = 1;
    for (;;) {
        if (size >= chain_len)
            break;
        size *= 2;
    }
    return size;
}

static aux_info *get_aux_info(const char *aux_name)
{
    sds key = sdsnew(aux_name);
    struct dict_entry *entry = dict_find(aux_dict, key);
    sdsfree(key);
    if (entry == NULL) {
        return NULL;
    }
    return entry->val;
}

static int req_getauxblock(const char *aux_name, bool update)
{
    aux_info *info = get_aux_info(aux_name);
    if (info == NULL) {
        log_error("get_aux_info fail %s", aux_name);
        return -__LINE__;
    }

    json_t *message = json_object();
    json_object_set_new(message, "aux_name", json_string(aux_name));
    json_object_set_new(message, "timeout", json_real(10.0));
    json_object_set_new(message, "update", json_boolean(update));
    if (info->address != NULL) {
        json_object_set_new(message, "method", json_string("createauxblock"));
        json_t *params = json_array();
        json_array_append_new(params, json_string(info->address));
        json_object_set_new(message, "params", params);
    } else {
        json_object_set_new(message, "method", json_string("getauxblock"));
        json_object_set_new(message, "params", json_array());
    }

    int ret = nw_job_add(job, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail %s: %d", aux_name, ret);
        return -__LINE__;
    }

    return 0;
}

static int req_getblockcount(const char *aux_name)
{
    json_t *message = json_object();
    json_object_set_new(message, "aux_name", json_string(aux_name));
    json_object_set_new(message, "timeout", json_real(10.0));
    json_object_set_new(message, "method", json_string("getblockcount"));
    json_object_set_new(message, "params", json_array());

    int ret = nw_job_add(job, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail %s: %d", aux_name, ret);
        return -__LINE__;
    }
    return 0;
}

static json_t *rpc_getauxblock(coin_rpc *coin, sds address)
{
    double start = current_timestamp();

    json_t *r = NULL;
    if (address == NULL) {
        r = coin_rpc_cmd(coin, 1, "getauxblock", NULL);
    } else {
        json_t *params = json_array();
        json_array_append_new(params, json_string(address));
        r = coin_rpc_cmd(coin, 1, "createauxblock", params);
        log_trace("name: %s, host: %s, port: %d, user: %s, pass: %s, address: %s", coin->name, coin->list[0].daemon.host, coin->list[0].daemon.port, coin->list[0].daemon.user, coin->list[0].daemon.pass, address);
        json_decref(params);
    }

    double end = current_timestamp();
    log_trace("name: %s getauxblock cost time: %f", coin->name, end - start);
    if (r == NULL) {
        log_error("name: %s rpc getauxblock fail", coin->name);
        return NULL;
    }
    return r;
}

static void on_job(nw_job_entry *entry, void *privdata)
{
    json_t *message = entry->request;
    aux_info *info = get_aux_info(json_string_value(json_object_get(message, "aux_name")));
    if (!info) {
        log_error("find aux_info: %s fail", json_string_value(json_object_get(message, "aux_name")));
        return;
    }

    double start = current_timestamp();
    entry->reply = coin_rpc_cmd(info->coin,
            json_number_value(json_object_get(message, "timeout")),
            json_string_value(json_object_get(message, "method")),
            json_object_get(message, "params"));
    double end = current_timestamp();

    log_trace("aux rpc command: %s cost: %f, name: %s", json_string_value(json_object_get(message, "method")), end - start, json_string_value(json_object_get(message, "aux_name")));
}

static void on_finish(nw_job_entry *entry)
{
    json_t *message = entry->request;
    const char *method = json_string_value(json_object_get(message, "method"));
    const char *aux_name = json_string_value(json_object_get(message, "aux_name"));
    aux_info *info = get_aux_info(aux_name);
    if (!info) {
        log_error("find aux_info: %s fail", aux_name);
        return;
    }

    json_t *reply = entry->reply;
    if (reply == NULL) {
        log_fatal("%s aux rpc %s fail", aux_name, method);
        return;
    }

    if (strcmp(method, "getblockcount") == 0) {
        int height = json_integer_value(reply);
        if (height > info->height) {
            log_info("aux height update to %s: %d", aux_name, height);
            info->height = height;
            req_getauxblock(aux_name, true);
        }
    } else if (strcmp(method, "createauxblock") == 0) {
        if (info->block != NULL)
            json_decref(info->block);

        json_incref(reply);
        info->block = reply;
        info->update_time = time(NULL);
        log_info("get new %s job", aux_name);
        if (json_boolean_value(json_object_get(message, "update"))) {
            log_info("%s job update", aux_name);
            int ret = on_aux_update();
            if (ret < 0) {
                log_error("on_aux_update fail: %d", ret);
            }
        }
    } else if (strcmp(method, "submitauxblock") == 0) {
        json_t *params = json_object_get(message, "params");
        const char *aux_hash = json_string_value(json_array_get(params, 0));
        if (json_is_false(reply)) {
            log_fatal("submit aux block fail, name: %s, hash: %s", aux_name, aux_hash);
        } else {
            log_info("submit aux block success, name: %s, hash: %s", aux_name, aux_hash);
        } 
    } else if (strcmp(method, "getauxblock") == 0) {
        json_t *params = json_object_get(message, "params");
        if (json_array_size(params) == 0) {
            if (info->block != NULL)
                json_decref(info->block);
            json_incref(reply);
            info->block = reply;
            info->update_time = time(NULL);
            log_info("get new %s job", aux_name);
            if (json_boolean_value(json_object_get(message, "update"))) {
                log_info("%s job update", aux_name);
                int ret = on_aux_update();
                if (ret < 0) {
                    log_error("on_aux_update fail: %d", ret);
                }
            }
        } else {
            const char *aux_hash = json_string_value(json_array_get(params, 0));
            if (json_is_false(reply)) {
                log_fatal("submit aux block fail, name: %s, hash: %s", aux_name, aux_hash);
            } else {
                log_info("submit aux block success, name: %s, hash: %s", aux_name, aux_hash);
            }
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
    dict_iterator *iter = dict_get_iterator(aux_dict);
    if (iter == NULL)
        return;

    time_t now = time(NULL);
    dict_entry *entry;
    while ((entry = dict_next(iter)) != NULL) {
        req_getblockcount(entry->key);
        aux_info *info = entry->val;
        if (now - info->update_time >= settings.aux_job_timeout) {
            req_getauxblock(entry->key, false);
        }
    }
    dict_release_iterator(iter);
}

static uint32_t aux_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sdslen((sds)key));
}

static int aux_dict_key_compare(const void *key1, const void *key2)
{
    return sdscmp((sds)key1, (sds)key2);
}

static void aux_dict_key_free(void *key)
{
    sdsfree((sds)key);
}

static void aux_info_free(aux_info *info)
{
    if (info->coin) {
        coin_rpc_release(info->coin);
    }
    if (info->block) {
        json_decref(info->block);
    }
    if (info->address) {
        sdsfree(info->address);
    }
    free(info);
}

static void aux_dict_val_free(void *val)
{
    aux_info_free((aux_info *)val);
}

static bool check_conflicted(int *arr, int len, int element)
{
    for (int i = 0; i < len; i++) {
        if (arr[i] == element)
            return true;
    }
    return false;
}

static int init_aux_dict()
{
    dict_types type;
    memset(&type, 0, sizeof(type));
    type.hash_function  = aux_dict_hash_func;
    type.key_compare    = aux_dict_key_compare;
    type.key_destructor = aux_dict_key_free;
    type.val_destructor = aux_dict_val_free;
    aux_dict = dict_create(&type, 64);
    if (aux_dict == NULL) {
        return -__LINE__;
    }

    int *merkle_index_arr = malloc(sizeof(int) * settings.aux_coin_count);
    merkle_size = cal_merkle_size(settings.aux_coin_count);
    merkle_size = settings.aux_merkle_size;
    memset(merkle_index_arr, 0, sizeof(int) * settings.aux_coin_count);
    for (int i = 0; i < settings.aux_coin_count; i++) {
        aux_info *info = (aux_info *)malloc(sizeof(aux_info));
        memset(info, 0, sizeof(aux_info));
        info->coin = coin_rpc_create(&settings.aux_coin[i]);
        if (info->coin == NULL)
            return -__LINE__;

        if (settings.aux_address[i] != NULL) {
            info->address = sdsnew(settings.aux_address[i]);
            log_info("coin: %s, address: %s", settings.aux_coin[i].name, info->address);
        } else {
            log_info("coin: %s, address: NULL", settings.aux_coin[i].name);
        }

        info->block = rpc_getauxblock(info->coin, info->address);

        if (info->block == NULL)
            return -__LINE__;
        info->update_time = time(NULL);

        json_t *chain_id = json_object_get(info->block, "chainid");
        if (!json_is_integer(chain_id)) 
            return -__LINE__;

        info->chain_id = json_integer_value(chain_id);
        info->merkle_index = cal_merkle_index(info->chain_id, settings.aux_merkle_nonce, merkle_size);
        log_info("aux: %s chain_id: %d merkle_index: %d", settings.aux_coin[i].name, info->chain_id, info->merkle_index);
        if (i > 0 && check_conflicted(merkle_index_arr, i, info->merkle_index)) {
            log_error("merkle_index conflicted");
            return -__LINE__;
        }

        merkle_index_arr[i] = info->merkle_index;
        sds key = sdsnew(settings.aux_coin[i].name);
        dict_add(aux_dict, key, info);
    }
    free(merkle_index_arr);
    return 0;
}

int32_t get_merkle_size()
{
    return merkle_size;
}

int init_aux(void)
{
    ERR_RET(init_aux_dict());

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

int on_aux_blocknotify(const char *aux_name)
{
    if (job == NULL)
        return 0;

    return req_getblockcount(aux_name);
}

int submit_aux_block(const char *aux_name, const char *aux_hash, const char *aux_pow)
{
    aux_info *info = get_aux_info(aux_name);
    if (!info) {
        log_error("find aux_info: %s fail", aux_name);
        return __LINE__;
    }

    json_t *message = json_object();
    json_object_set_new(message, "aux_name", json_string(aux_name));
    json_object_set_new(message, "timeout", json_real(10.0));
    if (info->address) {
        json_object_set_new(message, "method", json_string("submitauxblock"));
    } else {
        json_object_set_new(message, "method", json_string("getauxblock"));
    }

    json_t *params = json_array();
    json_array_append_new(params, json_string(aux_hash));
    json_array_append_new(params, json_string(aux_pow));
    json_object_set_new(message, "params", params);

    int ret = nw_job_add(job, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail %s: %d", aux_name, ret);
        return -__LINE__;
    }

    return 0;
}

