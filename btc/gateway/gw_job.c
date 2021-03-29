/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/04, create
 */

# include "gw_job.h"
# include "gw_worker.h"
# include "gw_config.h"
# include "ut_pack.h"

static rpc_clt *clt;
static dict_t *job_dict;
static dict_t *share_dict;
static dict_t *ban_dict;
static struct job *curr_job;
static double diff1_bignum;

static void job_aux_free(aux_meta *aux)
{
    if (aux->aux_name) {
        sdsfree(aux->aux_name);
    }
    if (aux->aux_hash) {
        sdsfree(aux->aux_hash);
    }
}

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
    if (job->aux_count > 0 && job->auxes) {
        for (int i = 0; i < job->aux_count; i++) {
            job_aux_free(&job->auxes[i]);
        }
        free(job->auxes);
    }
    sdsfree(job->job_raw);
    free(job);
}

static void on_connect(nw_ses *ses, bool result)
{
    if (result) {
        log_info("connect jobmaster: %s success", nw_sock_human_addr(&ses->peer_addr));
    } else {
        log_error("connect jobmaster: %s fail", nw_sock_human_addr(&ses->peer_addr));
    }
}

static int job_set_aux(json_t *aux_objs, struct job *job) 
{
    if (!json_is_array(aux_objs)) {
        return -__LINE__;
    }

    job->aux_count = json_array_size(aux_objs);
    int ret = 0;
    if (job->aux_count > 0) {
        job->auxes = (aux_meta *)malloc(sizeof(aux_meta) * job->aux_count);
        memset(job->auxes, 0, sizeof(aux_meta) * job->aux_count);
        for (int i = 0; i < job->aux_count; i++) {
            json_t *aux_obj = json_array_get(aux_objs, i);
            if (!aux_obj || !json_is_object(aux_obj)) {
                ret = -__LINE__;
                break;
            }
            json_t *aux_target_obj = json_object_get(aux_obj, "aux_target");
            if (!aux_target_obj || !json_is_string(aux_target_obj)) {
                ret = -__LINE__;
                break;
            }
            sds aux_target_bin = hex2bin(json_string_value(aux_target_obj));
            if (!aux_target_bin || sdslen(aux_target_bin) != 32) {
                if (aux_target_bin)
                    sdsfree(aux_target_bin);
                ret = -__LINE__;
                break;
            }
            memcpy(job->auxes[i].aux_target, aux_target_bin, sizeof(job->auxes[i].aux_target));
            sdsfree(aux_target_bin);
            
            json_t *aux_name_obj = json_object_get(aux_obj, "aux_name");
            if (!aux_name_obj || !json_is_string(aux_name_obj)) {
                ret = -__LINE__;
                break;
            }
            job->auxes[i].aux_name = sdsnew(json_string_value(aux_name_obj));

            json_t *aux_hash_obj = json_object_get(aux_obj, "aux_hash");
            if (!aux_hash_obj || !json_is_string(aux_hash_obj)){
                ret = -__LINE__;
                break;
            }
            job->auxes[i].aux_hash = sdsnew(json_string_value(aux_hash_obj));
            log_info("set aux, aux_name: %s aux_hash: %s, aux_target: %s", json_string_value(aux_name_obj), json_string_value(aux_hash_obj), json_string_value(aux_target_obj));
        }
    }
    return ret;
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

    json_t *aux_objs = json_object_get(message, "auxes");
    if (!aux_objs) {
        return 0;
    }
    return job_set_aux(aux_objs, job);
}

static int on_job_update(rpc_pkg *pkg)
{
    json_t *message = json_loadb(pkg->body, pkg->body_size, 0, NULL);
    if (message== NULL) {
        sds dump = hexdump(pkg->body, pkg->body_size);
        log_error("decode message fail, request message:\n%s", dump);
        sdsfree(dump);
        return -__LINE__;
    }

    struct job *job = malloc(sizeof(struct job));
    memset(job, 0, sizeof(struct job));
    int ret = decode_job(message, job);
    if (ret < 0) {
        sds dump = hexdump(pkg->body, pkg->body_size);
        log_error("decode_job fail: %d, request: \n%s", ret, dump);
        sdsfree(dump);
        job_free(job);
        json_decref(message);
        return -__LINE__;
    }

    job->job_raw = sdsnewlen(pkg->body, pkg->body_size);
    job->job_raw = sdscat(job->job_raw, "\n");

    json_t *clean_jobs_obj = json_object_get(message, "clean_jobs");
    if (!clean_jobs_obj || !json_is_boolean(clean_jobs_obj)) {
        job_free(job);
        json_decref(message);
        return -__LINE__;
    }
    bool clean_jobs = json_boolean_value(clean_jobs_obj);
    if (clean_jobs) {
        log_info("clean job, clear job dict and share dict");
        dict_clear(job_dict);
        dict_mark_clear(share_dict);
        curr_job = NULL;
    }
    json_decref(message);

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

    sds body = sdsnewlen(pkg->body, pkg->body_size);
    log_debug("update job: %s, %s", job->job_id, body);
    sdsfree(body);

    log_info("broadcast job: %s", job->job_id);
    ret = broadcast_job(job, clean_jobs);
    if (ret < 0) {
        log_error("broadcast_job: %s fail", key);
        return -__LINE__;
    }

    return 0;
}

static void add_ban_ip(const char *ip)
{
    sds key = sdsnew(ip);
    dict_add(ban_dict, key, NULL);
}

static void del_ban_ip(const char *ip)
{
    sds key = sdsnew(ip);
    dict_delete(ban_dict, key);
    sdsfree(key);
}

static int on_update_ban(rpc_pkg *pkg)
{
    json_t *message = json_loadb(pkg->body, pkg->body_size, 0, NULL);
    if (message == NULL) {
        sds dump = hexdump(pkg->body, pkg->body_size);
        log_error("decode message fail, request message:\n%s", dump);
        sdsfree(dump);
        return -__LINE__;
    }

    json_t *ip_list = json_object_get(message, "ip");
    if (!ip_list || !json_is_array(ip_list)) {
        json_decref(message);
        return -__LINE__;
    }
    json_t *op = json_object_get(message, "op");
    if (!op || !json_is_string(op)) {
        json_decref(message);
        return -__LINE__;
    }

    size_t ip_count = json_array_size(ip_list);
    if (strcmp(json_string_value(op), "add") == 0) {
        for (size_t i = 0; i < ip_count; ++i) {
            const char *ip = json_string_value(json_array_get(ip_list, i));
            log_info("add banned ip: %s", ip);
            add_ban_ip(ip);
        }
    } else if (strcmp(json_string_value(op), "del") == 0) {
        for (size_t i = 0; i < ip_count; ++i) {
            const char *ip = json_string_value(json_array_get(ip_list, i));
            log_info("del banned ip: %s", ip);
            del_ban_ip(ip);
        }
    } else {
        log_error("unkown op: %s", json_string_value(op));
        json_decref(message);
        return -__LINE__;
    }
    
    json_decref(message);
    return 0;
}

static void on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    int ret;
    switch (pkg->command) {
    case CMD_UPDATE_JOB:
        ret = on_job_update(pkg);
        if (ret < 0) {
            log_error("on_job_update fail: %d", ret);
        }
        break;
    case CMD_UPDATE_BAN:
        ret = on_update_ban(pkg);
        if (ret < 0) {
            log_error("on_update_ban fail: %d", ret);
        }
        break;
    default:
        log_error("unknown command: %u", pkg->command);
        break;
    }
}

static int init_clt(void)
{
    rpc_clt_type type;
    memset(&type, 0, sizeof(type));
    type.on_connect = on_connect;
    type.on_recv_pkg = on_recv_pkg;

    clt = rpc_clt_create(&settings.job, &type);
    if (clt == NULL)
        return -__LINE__;
    if (rpc_clt_start(clt) < 0)
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

static uint32_t share_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(&key, sizeof(key));
}
static int share_dict_key_compare(const void *key1, const void *key2)
{
    return key1 - key2;
}

static uint32_t ban_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sdslen((sds)key));
}
static int ban_dict_key_compare(const void *key1, const void *key2)
{
    return sdscmp((sds)key1, (sds)key2);
}
static void ban_dict_key_free(void *key)
{
    sdsfree((sds)key);
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

    dict_types type_share;
    memset(&type_share, 0, sizeof(type_share));
    type_share.hash_function = share_dict_hash_func;
    type_share.key_compare   = share_dict_key_compare;
    share_dict = dict_create(&type_share, 64);
    if (share_dict == NULL)
        return -__LINE__;

    dict_types type_ban;
    memset(&type_ban, 0, sizeof(type_ban));
    type_ban.hash_function  = ban_dict_hash_func;
    type_ban.key_compare    = ban_dict_key_compare;
    type_ban.key_destructor = ban_dict_key_free;
    ban_dict = dict_create(&type_ban, 64);
    if (ban_dict == NULL)
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

int init_job(void)
{
    ERR_RET(init_clt());
    ERR_RET(init_dict());
    ERR_RET(init_diff());

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

sds get_real_coinbase1(struct job *job, char *user, uint32_t worker_id, uint32_t nonce_id)
{
    size_t left_size = 100 - 5 - 1 - 17;
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
    pack_char(&p, &left, 16);
    uint32_t id = (worker_id << 16) + job->job_id_num;
    pack_uint32_le(&p, &left, id);
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

sds get_real_coinbase1_ext(struct job *job, char *user, uint32_t agent_id, uint32_t nonce_id)
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
    pack_uint32_le(&p, &left, agent_id);
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

bool is_share_exist(const char *block_hash)
{
    void *key;
    memcpy(&key, block_hash + 32 - sizeof(key), sizeof(key));
    dict_entry *entry = dict_find(share_dict, key);
    if (entry) {
        return true;
    }
    dict_add(share_dict, key, NULL);
    return false;
}

bool is_valid_main_block(struct job *job, const char *header_hash)
{
    if (memcmp(header_hash, job->target, 32) <= 0) {
        return true;
    }
    return false;
}

int on_found_block(const char *job_id, const char *type, const char *name, const char *hash, const char *block_head, const sds coinbase)
{
    sds block_head_hex = bin2hex(block_head, 80);
    sds coinbase_hex = bin2hex(coinbase, sdslen(coinbase));

    json_t *message = json_object();
    json_object_set_new(message, "job_id", json_string(job_id));
    json_object_set_new(message, "hash", json_string(hash));
    json_object_set_new(message, "block_head", json_string(block_head_hex));
    json_object_set_new(message, "coinbase", json_string(coinbase_hex));
    json_object_set_new(message, "type", json_string(type));
    json_object_set_new(message, "name", json_string(name));
    sdsfree(block_head_hex);
    sdsfree(coinbase_hex);

    char *message_data = json_dumps(message, 0);
    if (message_data == NULL) {
        json_decref(message);
        return -__LINE__;
    }
    json_decref(message);

    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.command = CMD_FOUND_BLOCK;
    pkg.pkg_type = RPC_PKG_TYPE_REQUEST;
    pkg.body_size = strlen(message_data);
    pkg.body = message_data;

    int ret = rpc_clt_send(clt, &pkg);
    if (ret < 0) {
        log_error("rpc_send to jobmaster: %s fail", nw_sock_human_addr(&clt->raw_clt->ses.peer_addr));
        free(message_data);
        return -__LINE__;
    }
    free(message_data);

    return 0;
}

bool is_ip_banned(const char *ip)
{
    sds key = sdsnew(ip);
    dict_entry *entry = dict_find(ban_dict, key);
    if (entry) {
        sdsfree(key);
        return true;
    }
    sdsfree(key);
    return false;
}

