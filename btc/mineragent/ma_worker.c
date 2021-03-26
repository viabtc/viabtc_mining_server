/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/02, create
 */

# include "ma_job.h"
# include "ma_config.h"
# include "ma_worker.h"
# include "ut_pack.h"
# include "ut_misc.h"
# include "ut_merkle.h"

static rpc_clt *listener_clt;
static nw_svr *worker_svr;
static nw_cache *worker_cache;
static nw_timer worker_timer;

uint32_t worker_id;
static uint32_t miner_id_counter;
static uint64_t subscription_counter;
static uint64_t extra_nonce1_counter;

# define MAX_USER_NAME_LEN          64
# define MAX_WORKER_NAME_LEN        64
# define MAX_USER_AGENT_LEN         64
# define EXTRA_NONCE2_SIZE          8
//recommended, BIP9 security
# define VERSION_MASK_DEFAULT       536862720

# define VARDIFF_RETARGET_SHARE 30
# define VARDIFF_BUF_SIZE (VARDIFF_RETARGET_SHARE * 3)

typedef struct vardiff_buf {
    int         use;
    int         pos;
    double      data[VARDIFF_BUF_SIZE];
} vardiff_buf;

struct client_info {
    double      connect_time;
    double      last_active_time;
    bool        subscribed;
    bool        authorized;
    char        user[MAX_USER_NAME_LEN + 1];
    char        worker[MAX_WORKER_NAME_LEN + 1];
    char        user_agent[MAX_USER_AGENT_LEN + 1];
    char        subscription_id[17];
    uint32_t    miner_id;
    uint32_t    nonce_id;
    char        extra_nonce1[9];
    bool        user_suggest_diff;
    int         difficulty_last;
    int         difficulty;
    vardiff_buf vardiff;
    double      last_retarget_time;
    uint64_t    last_retarget_share;
    double      last_share_time;
    uint64_t    share_valid;
    uint64_t    share_error;
    double      share_pow;
    uint32_t    version_mask;
    uint32_t    version_mask_miner;
};

static void vardiff_append(struct vardiff_buf *vardiff, double time)
{
    vardiff->data[vardiff->pos++] = time;
    vardiff->pos %= VARDIFF_BUF_SIZE;
    if (vardiff->use < VARDIFF_BUF_SIZE)
        vardiff->use++;
}

static double vardiff_avg(struct vardiff_buf *vardiff)
{
    int count = VARDIFF_BUF_SIZE;
    if (vardiff->use < VARDIFF_BUF_SIZE) {
        count = vardiff->pos;
    }
    double total = 0;
    for (int i = 0; i < count; ++i) {
        total += vardiff->data[i];
    }
    return total / count;
}

static void vardiff_reset(struct vardiff_buf *vardiff)
{
    vardiff->use = 0;
    vardiff->pos = 0;
}

static int retarget_on_new_share(struct client_info *info)
{
    double now = current_timestamp();
    double interval = now - info->last_share_time;
    info->last_share_time = now;
    vardiff_append(&info->vardiff, interval);
    if (!((info->share_valid - info->last_retarget_share) >= VARDIFF_RETARGET_SHARE ||
          (now - info->last_retarget_time) >= settings.retarget_time)) {
        return 0;
    }
    info->last_retarget_time = now;
    info->last_retarget_share = info->share_valid;

    double avg = vardiff_avg(&info->vardiff);
    int new_diff = 0;
    if (avg > settings.target_time) {
        if (avg / settings.target_time <= 1.5) {
            return 0;
        } else {
            new_diff = info->difficulty / 2;
        }
    } else {
        if (avg / settings.target_time >= 0.7) {
            return 0;
        } else {
            new_diff = info->difficulty * 2;
        }
    }

    if (new_diff < settings.diff_min)
        new_diff = settings.diff_min;
    if (new_diff > settings.diff_max)
        new_diff = settings.diff_max;

    if (new_diff != info->difficulty) {
        info->difficulty_last = info->difficulty;
        info->difficulty = new_diff;
        vardiff_reset(&info->vardiff);
        log_debug("avg share time: %f, target: %d, retarget difficulty to: %d", avg, settings.target_time, new_diff);
        return 1;
    }

    return 0;
}

static int worker_decode_pkg(nw_ses *ses, void *data, size_t max)
{
    char *s = data;
    for (size_t i = 0; i < max; ++i) {
        if (s[i] == '\n')
            return i + 1;
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

static int set_difficulty(nw_ses *ses, int difficulty)
{
    json_t *message = json_object();
    json_object_set_new(message, "id", json_null());
    json_object_set_new(message, "method", json_string("mining.set_difficulty"));

    json_t *params = json_array();
    json_array_append_new(params, json_integer(difficulty));
    json_object_set_new(message, "params", params);

    send_json(ses, message);
    json_decref(message);

    log_debug("connection: %"PRIu64":%s set difficulty to: %d", ses->id, nw_sock_human_addr(&ses->peer_addr), difficulty);

    struct client_info *info = ses->privdata;
    submit_sync(info->miner_id, info->nonce_id, info->extra_nonce1, info->difficulty);

    return 0;
}

static int send_job(nw_ses *ses, struct job *job, bool clean_job)
{
    struct client_info *info = ses->privdata;    
    sds real_coinbase1 = get_real_coinbase1(job, info->user, info->nonce_id);
    sds coinbase1_hex = bin2hex(real_coinbase1, sdslen(real_coinbase1));

    json_t *params = json_array();
    json_array_append_new(params, json_string(job->job_id));
    json_array_append_new(params, json_string(job->prevhash_hex));
    json_array_append_new(params, json_string(coinbase1_hex));
    json_array_append_new(params, json_string(job->coinbase2_hex));
    json_array_append    (params, job->merkle_json);
    json_array_append_new(params, json_string(job->version_hex));
    json_array_append_new(params, json_string(job->nbits_hex));
    json_array_append_new(params, json_string(job->curtime_hex));
    json_array_append_new(params, clean_job ? json_true() : json_false());
    sdsfree(real_coinbase1);
    sdsfree(coinbase1_hex);

    json_t *message = json_object();
    json_object_set_new(message, "id", json_null());
    json_object_set_new(message, "method", json_string("mining.notify"));
    json_object_set_new(message, "params", params);

    send_json(ses, message);
    json_decref(message);

    log_debug("connection: %"PRIu64":%s send new job: %s", ses->id, nw_sock_human_addr(&ses->peer_addr), job->job_id);

    return 0;
}

static int send_curr_job(nw_ses *ses)
{
    struct job *job = get_curr_job();
    if (job == NULL) {
        log_error("get_curr_job fail");
        return -__LINE__;
    }
    int ret = send_job(ses, job, true);
    if (ret < 0) {
        log_error("send_job fail: %d", ret);
        return -__LINE__;
    }

    return 0;
}

static int send_error(nw_ses *ses, json_t *id, int error_code, const char *error_msg)
{
    json_t *error = json_array();
    json_array_append_new(error, json_integer(error_code));
    json_array_append_new(error, json_string(error_msg));
    json_array_append_new(error, json_null());

    json_t *message = json_object();
    json_object_set(message, "id", id);
    json_object_set_new(message, "error", error);
    json_object_set_new(message, "result", json_null());

    send_json(ses, message);
    json_decref(message);

    struct client_info *info = ses->privdata;
    log_info("connection: %"PRIu64":%s, user: %s, worker: %s, error code: %d, message: %s", ses->id, \
            nw_sock_human_addr(&ses->peer_addr), info->user, info->worker, error_code, error_msg);
    info->share_error++;

    return 0;
}

static int send_ok(nw_ses *ses, json_t *id)
{
    json_t *message = json_object();
    json_object_set(message, "id", id);
    json_object_set_new(message, "error", json_null());
    json_object_set_new(message, "result", json_true());

    send_json(ses, message);
    json_decref(message);

    return 0;
}

static int handle_configure(nw_ses *ses, struct client_info *info, json_t *id, json_t *params)
{
    if (json_array_size(params) < 1) {
        return send_error(ses, id, 31, "invalid config");
    }

    json_t *versrion_rolling_obj = json_array_get(params, 0);
    if (versrion_rolling_obj && json_is_array(versrion_rolling_obj) && json_array_size(versrion_rolling_obj) >= 1) {
        json_t *param1 = json_array_get(versrion_rolling_obj, 0);
        if (param1 && json_is_string(param1)) {
            const char *param1_str = json_string_value(param1);
            if (strcmp(param1_str, "version-rolling") == 0) {

                uint32_t _version_mask = 0;
                json_t *versrion_rolling_param2 = json_array_get(params, 1);
                if (versrion_rolling_param2 && json_is_object(versrion_rolling_param2)) {
                    json_t *version_mask_obj = json_object_get(versrion_rolling_param2, "version-rolling.mask");
                    if (version_mask_obj && json_is_string(version_mask_obj)) {
                        _version_mask = strtoul(json_string_value(version_mask_obj), NULL, 16);
                    }
                }

                info->version_mask_miner = _version_mask;
                info->version_mask = _version_mask & VERSION_MASK_DEFAULT;

                char version_mask_str[10] = {0};
                sprintf(version_mask_str, "%08x", info->version_mask);

                json_t *result = json_object();
                json_object_set_new(result, "version-rolling", json_true());
                json_object_set_new(result, "version-rolling.mask", json_string(version_mask_str));

                json_t *message = json_object();
                json_object_set(message, "id", id);
                json_object_set_new(message, "result", result);
                json_object_set_new(message, "error", json_null());

                send_json(ses, message);
                json_decref(message);

                json_t *params = json_array();
                json_array_append_new(params, json_string(version_mask_str));

                message = json_object();
                json_object_set(message, "id", json_null());
                json_object_set_new(message, "method", json_string("mining.set_version_mask"));
                json_object_set_new(message, "params", params);

                json_object_set_new(message, "error", json_null());

                send_json(ses, message);
                json_decref(message);
            }
        }
    }
    return 0;
}

static int handle_subscribe(nw_ses *ses, struct client_info *info, json_t *id, json_t *params)
{
    if (json_is_array(params) && json_array_size(params) > 0) {
        json_t *user_agent = json_array_get(params, 0);
        if (json_is_string(user_agent)) {
            strncpy(info->user_agent, json_string_value(user_agent), sizeof(info->user_agent) - 1);
        }
    }

    json_t *subscriptions_difficulty = json_array();
    json_array_append_new(subscriptions_difficulty, json_string("mining.set_difficulty"));
    json_array_append_new(subscriptions_difficulty, json_string(info->subscription_id));

    json_t *subscription_nodify = json_array();
    json_array_append_new(subscription_nodify, json_string("mining.notify"));
    json_array_append_new(subscription_nodify, json_string(info->subscription_id));

    json_t *subscriptions = json_array();
    json_array_append_new(subscriptions, subscriptions_difficulty);
    json_array_append_new(subscriptions, subscription_nodify);

    json_t *result = json_array();
    json_array_append_new(result, subscriptions);
    json_array_append_new(result, json_string(info->extra_nonce1));
    json_array_append_new(result, json_integer(EXTRA_NONCE2_SIZE));

    json_t *message = json_object();
    json_object_set(message, "id", id);
    json_object_set_new(message, "result", result);
    json_object_set_new(message, "error", json_null());

    send_json(ses, message);
    json_decref(message);

    info->subscribed = true;
    log_debug("connection: %"PRIu64":%s subscribe, subscribe id: %s", ses->id, nw_sock_human_addr(&ses->peer_addr), info->subscription_id);

    return 0;
}

static bool is_valid_user(const char *name)
{
    size_t len = strlen(name);
    if (len == 0 || len > MAX_USER_NAME_LEN)
        return false;
    for (size_t i = 0; i < len; ++i) {
        if (!isalnum(name[i]))
            return false;
    }
    return true;
}

static bool is_valid_worker(const char *name)
{
    size_t len = strlen(name);
    if (len == 0 || len > MAX_WORKER_NAME_LEN)
        return false;
    for (size_t i = 0; i < len; ++i) {
        if (!isalnum(name[i]))
            return false;
    }
    return true;
}

static int get_account_info(const char *account, char *user, char *worker)
{
    char *_account = strdup(account);
    strclearblank(_account);
    char *_user = _account;
    char *_worker = NULL;
    const char *tokens = ".:-_";
    strtok(_account, tokens);
    char *pch = strtok(NULL, tokens);
    if (pch) {
        _worker = pch;
    }
    if (!is_valid_user(_user)) {
        log_info("invalid user: %s, account: %s", _user, account);
        free(_account);
        return -__LINE__;
    }
    if (_worker && !is_valid_worker(_worker)) {
        log_info("invalid worker: %s, account: %s", _worker, account);
        free(_account);
        return -__LINE__;
    }

    strcpy(user, _user);
    strtolower(user);
    if (_worker) {
        strcpy(worker, _worker);
    } else {
        strcpy(worker, user);
    }
    strtolower(worker);
    free(_account);

    return 0;
}

static int handle_authorize(nw_ses *ses, struct client_info *info, json_t *id, json_t *params)
{
    if (!info->subscribed) {
        return -__LINE__;
    }

    json_t *account = json_array_get(params, 0);
    json_t *password = json_array_get(params, 1);
    if (!account || !json_is_string(account) || !password || !json_is_string(password))
        return -__LINE__;

    if (get_account_info(json_string_value(account), info->user, info->worker) < 0) {
        log_error("connection: %"PRIu64":%s, invalid account: %s", ses->id,
                nw_sock_human_addr(&ses->peer_addr), json_string_value(account));
        return -__LINE__;
    }

    json_t *message = json_object();
    json_object_set(message, "id", id);
    json_object_set_new(message, "result", json_true());
    json_object_set_new(message, "error", json_null());

    send_json(ses, message);
    json_decref(message);

    const char *pass = json_string_value(password);
    size_t pass_len = strlen(pass);
    if (pass_len >= 3 && (pass[0] == 'd' || pass[0] == 'D') && pass[1] == '=' && isdigit(pass[2])) {
        int difficulty = atoi(pass + 2);
        if (difficulty > 0) {
            info->user_suggest_diff = true;
            if (info->difficulty != difficulty) {
                info->difficulty = difficulty;
                info->difficulty_last = difficulty;
                log_debug("connection: %"PRIu64":%s, account: %s, password: %s, user suggest difficulty: %d", ses->id,
                        nw_sock_human_addr(&ses->peer_addr), json_string_value(account), pass, info->difficulty);
                if (info->authorized) {
                    ERR_RET(set_difficulty(ses, info->difficulty));
                }
            }
        }
    }

    if (!info->authorized) {
        ERR_RET(set_difficulty(ses, info->difficulty));
        ERR_RET(send_curr_job(ses));
        info->authorized = true;
        submit_event(info->user, info->worker, "connected");
        log_debug("connection: %"PRIu64":%s authorized, account:%s, password: %s, user: %s, worker: %s", ses->id,
                nw_sock_human_addr(&ses->peer_addr), json_string_value(account), json_string_value(password), info->user, info->worker);
    }

    return 0;
}

static int get_block_head(char *head, struct job *job, struct client_info *info, const char *extra_nonce2, const char *ntime, const char *nonce, uint32_t version_mask)
{
    if (strlen(extra_nonce2) != 8)
        return -__LINE__;
    if (strlen(ntime) != 8)
        return -__LINE__;
    if (strlen(nonce) != 8)
        return -__LINE__;

    sds extra_nonce1_bin = hex2bin(info->extra_nonce1);
    sds extra_nonce2_bin = hex2bin(extra_nonce2);
    if (extra_nonce1_bin == NULL || extra_nonce2_bin == NULL) {
        sdsfree(extra_nonce1_bin);
        sdsfree(extra_nonce2_bin);
        return -__LINE__;
    }

    sds coinbase;
    coinbase = get_real_coinbase1(job, info->user, info->nonce_id);
    coinbase = sdscatsds(coinbase, extra_nonce1_bin);
    coinbase = sdscatsds(coinbase, extra_nonce2_bin);
    coinbase = sdscatsds(coinbase, job->coinbase2_bin);
    sdsfree(extra_nonce1_bin);
    sdsfree(extra_nonce2_bin);

    char root_hash[32];
    sha256d(coinbase, sdslen(coinbase), root_hash);
    get_merkle_root(root_hash, job->merkle_branch, job->merkle_branch_count);
    sdsfree(coinbase);

    uint32_t intime = strtoul(ntime, NULL, 16);
    uint32_t inonce = strtoul(nonce, NULL, 16);
    uint32_t version = (job->version & ~(info->version_mask)) | (version_mask & (info->version_mask));

    void *p = head;
    size_t left = 80;
    pack_uint32_le(&p, &left, version);
    pack_buf(&p, &left, job->prevhash_raw, sizeof(job->prevhash_raw));
    pack_buf(&p, &left, root_hash, sizeof(root_hash));
    pack_uint32_le(&p, &left, intime);
    pack_uint32_le(&p, &left, job->nbits);
    pack_uint32_le(&p, &left, inonce);

    return 0;
}

static int handle_submit(nw_ses *ses, struct client_info *info, json_t *id, json_t *params)
{
    if (!info->subscribed) {
        return send_error(ses, id, 25, "Not subscribed");
    }
    if (!info->authorized) {
        return send_error(ses, id, 24, "Unauthorized worker");
    }

    json_t *account = json_array_get(params, 0);
    if (!account || !json_is_string(account)) {
        return -__LINE__;
    }
    json_t *job_id = json_array_get(params, 1);
    if (!job_id || !json_is_string(job_id)) {
        return -__LINE__;
    }
    json_t *extra_nonce2 = json_array_get(params, 2);
    if (!extra_nonce2 || !json_is_string(extra_nonce2) || strlen(json_string_value(extra_nonce2)) != EXTRA_NONCE2_SIZE * 2) {
        return -__LINE__;
    }
    json_t *ntime = json_array_get(params, 3);
    if (!ntime || !json_is_string(ntime) || strlen(json_string_value(ntime)) != 8) {
        return -__LINE__;
    }
    json_t *nonce = json_array_get(params, 4);
    if (!nonce || !json_is_string(nonce) || strlen(json_string_value(nonce)) != 8) {
        return -__LINE__;
    }

    uint32_t version_mask = 0;
    if (json_array_size(params) >= 6) {
        json_t *mask_obj = json_array_get(params, 5);
        if (!mask_obj || !json_is_string(mask_obj)) {
            return -__LINE__;
        }
        version_mask = strtoul(json_string_value(mask_obj), NULL, 16);
    }

    if (version_mask != 0 && ((~info->version_mask_miner) & version_mask) != 0) {
        log_error("connection: %"PRIu64":%s, user: %s, worker: %s, check version_mask fail, info version_mask: %u, version_mask: %u",
                ses->id, nw_sock_human_addr(&ses->peer_addr), info->user, info->worker, info->version_mask, version_mask);
        return __LINE__;
    }

    if (get_account_info(json_string_value(account), info->user, info->worker) < 0) {
        log_error("connection: %"PRIu64":%s, invalid account: %s", ses->id,
                nw_sock_human_addr(&ses->peer_addr), json_string_value(account));
        return -__LINE__;
    }
    struct job *job = find_job(json_string_value(job_id));
    if (!job) {
        log_error("connection: %"PRIu64":%s, user: %s, worker: %s job: %s not found",
                ses->id, nw_sock_human_addr(&ses->peer_addr), info->user, info->worker, json_string_value(job_id));
        return send_error(ses, id, 21, "Job not found");
    }

    char block_head[80];
    int ret = get_block_head(block_head, job, info, json_string_value(extra_nonce2), json_string_value(ntime), json_string_value(nonce), version_mask);
    if (ret < 0) {
        log_error("get_block_head fail: %d, invalid argument", ret);
        return -__LINE__;
    }
    char block_hash[32];
    sha256d(block_head, sizeof(block_head), block_hash);
    reverse_mem(block_hash, sizeof(block_hash));

    double share_diff = get_share_difficulty(block_hash);
    int difficulty = info->difficulty;
    if ((share_diff / info->difficulty) < 0.999) {
        if ((share_diff / info->difficulty_last) < 0.999) {
            log_info("connection: %"PRIu64":%s user: %s, worker: %s, job: %s, Low difficulty share, difficulty: %f, require difficulty: %d",
                    ses->id, nw_sock_human_addr(&ses->peer_addr), info->user, info->worker, json_string_value(job_id), share_diff, difficulty);
            return send_error(ses, id, 23, "Low difficulty share");
        } else {
            difficulty = info->difficulty_last;
        }
    }

    sds share_hex = bin2hex(block_hash + 24, 8);
    log_debug("connection: %"PRIu64":%s, user: %s, worker: %s submit new share: %s, job: %s, difficulty: %f, require difficulty: %d, block_diff: %.4f",
            ses->id, nw_sock_human_addr(&ses->peer_addr), info->user, info->worker, share_hex, json_string_value(job_id), share_diff, difficulty, job->block_diff);
    sdsfree(share_hex);

    send_ok(ses, id);
    info->share_pow += difficulty;
    info->share_valid++;
    submit_share(info->miner_id, params, info->version_mask, info->version_mask_miner, version_mask);

    if (!info->user_suggest_diff) {
        ret = retarget_on_new_share(info);
        if (ret > 0) {
            set_difficulty(ses, info->difficulty);
        }
    }

    return 0;
}

static int handle_suggest_difficulty(nw_ses *ses, struct client_info *info, json_t *id, json_t *params)
{
    if (json_array_size(params) < 1) {
        return -__LINE__;
    }
    if (!json_is_number(json_array_get(params, 0))) {
        return -__LINE__;
    }

    int difficulty = abs(json_number_value(json_array_get(params, 0)));
    info->user_suggest_diff = true;
    info->difficulty = difficulty;
    info->difficulty_last = info->difficulty;

    send_ok(ses, id);
    set_difficulty(ses, info->difficulty);
    log_debug("connection: %"PRIu64":%s, user suggest difficulty: %d", ses->id, nw_sock_human_addr(&ses->peer_addr), difficulty);

    return 0;
}

static int handle_get_transactions(nw_ses *ses, struct client_info *info, json_t *id, json_t *params)
{
    json_t *message = json_object();
    json_object_set(message, "id", id);
    json_object_set_new(message, "result", json_array());
    json_object_set_new(message, "error", json_null());

    send_json(ses, message);
    json_decref(message);

    return 0;
}

static int handle_extranonce_subscribe(nw_ses *ses, struct client_info *info, json_t *id, json_t *params)
{
    return 0;
}

static void worker_on_recv_pkg(nw_ses *ses, void *data, size_t size)
{
    struct client_info *info = ses->privdata;
    info->last_active_time = current_timestamp();

    json_t *request = json_loadb(data, size - 1, 0, NULL);
    if (request == NULL) {
        goto decode_error;
    }
    json_t *id = json_object_get(request, "id");
    if (!id) {
        goto decode_error;
    }
    json_t *method = json_object_get(request, "method");
    if (!method || !json_is_string(method)) {
        goto decode_error;
    }
    json_t *params = json_object_get(request, "params");
    if (!params || !json_is_array(params)) {
        goto decode_error;
    }

    char *request_data = data;
    request_data[size - 1] = '\0';
    log_trace("connection: %"PRIu64":%s, recv: %s", ses->id, nw_sock_human_addr(&ses->peer_addr), request_data);

    int ret = 0;
    const char *_method = json_string_value(method);
    if (strcmp(_method, "mining.configure") == 0) {
        ret = handle_configure(ses, info, id, params);
    } else if (strcmp(_method, "mining.subscribe") == 0) {
        ret = handle_subscribe(ses, info, id, params);
    } else if (strcmp(_method, "mining.authorize") == 0) {
        ret = handle_authorize(ses, info, id, params);
    } else if (strcmp(_method, "mining.submit") == 0) {
        ret = handle_submit(ses, info, id, params);
    } else if (strcmp(_method, "mining.suggest_difficulty") ==  0) {
        ret = handle_suggest_difficulty(ses, info, id, params);
    } else if (strcmp(_method, "mining.get_transactions") == 0) {
        ret = handle_get_transactions(ses, info, id, params);
    } else if (strcmp(_method, "mining.extranonce.subscribe") == 0) {
        ret = handle_extranonce_subscribe(ses, info, id, params);
    } else {
        log_error("connection: %"PRIu64":%s, unknown method: %s, request: %s", ses->id,
                nw_sock_human_addr(&ses->peer_addr), _method, request_data);
    }

    if (ret < 0) {
        log_error("connection: %"PRIu64":%s, handle request fail: %d, request: %s", ses->id,
                nw_sock_human_addr(&ses->peer_addr), ret, request_data);
        nw_svr_close_clt(worker_svr, ses);
    }

    json_decref(request);
    return;

decode_error:
    if (request) {
        json_decref(request);
    }
    sds hex = hexdump(data, size - 1);
    log_error("connection: %"PRIu64":%s, decode request fail, request data: \n%s", ses->id, nw_sock_human_addr(&ses->peer_addr), hex);
    sdsfree(hex);
    nw_svr_close_clt(worker_svr, ses);

    return;
}

static void *worker_on_privdata_alloc(void *svr)
{
    void *cache = nw_cache_alloc(worker_cache);
    memset(cache, 0, worker_cache->size);
    return cache;
}

static void worker_on_privdata_free(void *svr, void *privdata)
{
    nw_cache_free(worker_cache, privdata);
}

static void worker_on_new_connection(nw_ses *ses)
{
    if (!is_stratum_ok()) {
        nw_svr_close_clt(worker_svr, ses);
        return;
    }

    struct client_info *info = ses->privdata;

    // update time
    info->connect_time = current_timestamp();
    info->last_active_time = info->connect_time;
    info->last_share_time = info->connect_time;

    // generate subscription id
    uint64_t id = ++subscription_counter;
    sprintf(info->subscription_id, "%016"PRIx64, id);

    // generate nonce 
    uint64_t nonce = ++extra_nonce1_counter;
    info->nonce_id = nonce >> 32;
    sprintf(info->extra_nonce1, "%08x", (uint32_t)nonce);

    // generate miner id
    info->miner_id = ++miner_id_counter;

    // init difficulty
    info->difficulty = settings.diff_default;
    info->difficulty_last = info->difficulty;
    info->last_retarget_time = info->connect_time;
    info->version_mask = 0;
    info->version_mask_miner = 0;

    log_info("connection: %"PRIu64":%s, new connection, subscription_id: %s, nonce_id: %x, miner_id: %u, extra_nonce1: %s", \
            ses->id, nw_sock_human_addr(&ses->peer_addr), info->subscription_id, info->nonce_id, info->miner_id, info->extra_nonce1);
}

static void worker_on_connection_close(nw_ses *ses)
{
    log_info("connection: %"PRIu64":%s, close", ses->id, nw_sock_human_addr(&ses->peer_addr));
    struct client_info *info = ses->privdata;
    if (info->authorized) {
        submit_event(info->user, info->worker, "disconnected");
    }
}

static void worker_on_error_msg(nw_ses *ses, const char *msg)
{
    if (ses->ses_type == NW_SES_TYPE_COMMON) {
        log_error("connection: %"PRIu64":%s error: %s", ses->id, nw_sock_human_addr(&ses->peer_addr), msg);
    } else {
        log_error("connection: %"PRIu64":%s error: %s", ses->id, nw_sock_human_addr(ses->host_addr), msg);
    }
}

static void worker_on_timer(nw_timer *timer, void *privdata)
{
    int connections = 0;
    double now = current_timestamp();

    nw_ses *curr = worker_svr->clt_list_head;
    nw_ses *next;
    while (curr) {
        next = curr->next;
        struct client_info *info = curr->privdata;
        if (now - info->last_active_time > settings.client_max_idle_time) {
            log_info("connection: %"PRIu64":%s idle too long, close", curr->id, nw_sock_human_addr(&curr->peer_addr));
            nw_svr_close_clt(worker_svr, curr);
        } else {
            if (info->authorized) {
                connections += 1;
            }
        }
        curr = next;
    }

    submit_status((time(NULL) / 60) * 60, connections);

    return;
}

static int init_worker_svr(void)
{
    nw_svr_type type;
    memset(&type, 0, sizeof(type));
    type.decode_pkg = worker_decode_pkg;
    type.on_recv_pkg = worker_on_recv_pkg;
    type.on_new_connection = worker_on_new_connection;
    type.on_connection_close = worker_on_connection_close;
    type.on_privdata_alloc = worker_on_privdata_alloc;
    type.on_privdata_free = worker_on_privdata_free;
    type.on_error_msg = worker_on_error_msg;

    worker_svr = nw_svr_create(&settings.svr, &type, NULL);
    if (worker_svr == NULL)
        return -__LINE__;
    // Here we don't start svr to bind and listen

    nw_timer_set(&worker_timer, 60.0, true, worker_on_timer, NULL);
    nw_timer_start(&worker_timer);

    worker_cache = nw_cache_create(sizeof(struct client_info));
    if (worker_cache == NULL)
        return -__LINE__;

    urandom(&worker_id, sizeof(worker_id));
    urandom(&miner_id_counter, sizeof(miner_id_counter));
    urandom(&subscription_counter, sizeof(subscription_counter));
    urandom(&extra_nonce1_counter, sizeof(extra_nonce1_counter));

    log_info("worker id: %u, subscription_counter: %#"PRIx64", extra_nonce1_counter: %#"PRIx64"", 
            worker_id, subscription_counter, extra_nonce1_counter);

    return 0;
}

static void listener_on_connect(nw_ses *ses, bool result)
{
    if (result) {
        log_info("connect listener success");
    } else {
        log_info("connect listener fail");
    }
}

static void listener_on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    return;
}

static void listener_on_recv_fd(nw_ses *ses, int fd)
{
    if (get_curr_job() == NULL) {
        log_error("job not got");
        close(fd);
        return;
    }
    if (nw_svr_add_clt_fd(worker_svr, fd) < 0) {
        log_error("nw_svr_add_clt_fd: %d fail: %s", fd, strerror(errno));
        close(fd);
    }
}

static int init_listener_clt(void)
{
    rpc_clt_cfg cfg;
    nw_addr_t addr;
    memset(&cfg, 0, sizeof(cfg));
    cfg.name = strdup("listener");
    cfg.addr_count = 1;
    cfg.addr_arr = &addr;
    if (nw_sock_cfg_parse(LISTENER_BIND, &addr, &cfg.sock_type) < 0)
        return -__LINE__;
    cfg.max_pkg_size = 1024;

    rpc_clt_type type;
    memset(&type, 0, sizeof(type));
    type.on_connect = listener_on_connect;
    type.on_recv_pkg = listener_on_recv_pkg;
    type.on_recv_fd = listener_on_recv_fd;

    listener_clt = rpc_clt_create(&cfg, &type);
    if (listener_clt == NULL)
        return -__LINE__;
    if (rpc_clt_start(listener_clt) < 0)
        return -__LINE__;

    return 0;
}

int get_extra_nonce_size()
{
    return 4 + EXTRA_NONCE2_SIZE;
}

int broadcast_job(struct job *job, bool clean_job)
{
    if (!worker_svr)
        return -__LINE__;

    json_t *params = json_array();
    json_array_append_new(params, json_string(job->job_id));
    json_array_append_new(params, json_string(job->prevhash_hex));
    json_array_append_new(params, json_string("coinbase1"));
    json_array_append_new(params, json_string(job->coinbase2_hex));
    json_array_append    (params, job->merkle_json);
    json_array_append_new(params, json_string(job->version_hex));
    json_array_append_new(params, json_string(job->nbits_hex));
    json_array_append_new(params, json_string(job->curtime_hex));
    json_array_append_new(params, clean_job ? json_true() : json_false());

    json_t *message = json_object();
    json_object_set_new(message, "id", json_null());
    json_object_set_new(message, "method", json_string("mining.notify"));
    json_object_set_new(message, "params", params);

    char *message_data = json_dumps(message, 0);
    if (message_data == NULL) {
        json_decref(message);
        return -__LINE__;
    }
    json_decref(message);

    char *ph = strstr(message_data, "coinbase1");
    if (ph == NULL) {
        free(message_data);
        return -__LINE__;
    }
    sds job1 = sdsnewlen(message_data, ph - message_data);
    sds job2 = sdsnewlen(ph + strlen("coinbase1"), strlen(message_data) - sdslen(job1) - strlen("coinbase1"));
    free(message_data);

    nw_ses *curr = worker_svr->clt_list_head;
    while (curr) {
        struct client_info *info = curr->privdata;
        if (info->authorized) {
            sds real_coinbase1 = get_real_coinbase1(job, info->user, info->nonce_id);
            sds coinbase1_hex = bin2hex(real_coinbase1, sdslen(real_coinbase1));

            sds job_data = sdsempty();
            job_data = sdscatsds(job_data, job1);
            job_data = sdscatsds(job_data, coinbase1_hex);
            job_data = sdscatsds(job_data, job2);
            job_data = sdscat(job_data, "\n");

            nw_ses_send(curr, job_data, sdslen(job_data));
            log_trace("connection: %"PRIu64":%s send: %s", curr->id, nw_sock_human_addr(&curr->peer_addr), job_data);

            sdsfree(real_coinbase1);
            sdsfree(coinbase1_hex);
            sdsfree(job_data);
        }
        curr = curr->next;
    }

    sdsfree(job1);
    sdsfree(job2);

    return 0;
}

int close_all_connection(void)
{
    nw_ses *curr = worker_svr->clt_list_head;
    while (curr) {
        nw_ses *next = curr->next;
        nw_svr_close_clt(worker_svr, curr);
        curr = next;
    }

    return 0;
}

int submit_sync_all(void)
{
    sds data = sdsempty();
    nw_ses *curr = worker_svr->clt_list_head;
    while (curr) {
        nw_ses *next = curr->next;
        struct client_info *info = curr->privdata;
        if (info->authorized) {
            json_t *params = json_array();
            json_array_append_new(params, json_integer(info->miner_id));
            json_array_append_new(params, json_integer(info->nonce_id));
            json_array_append_new(params, json_string(info->extra_nonce1));
            json_array_append_new(params, json_integer(info->difficulty));

            json_t *message = json_object();
            json_object_set_new(message, "id", json_integer(current_timestamp() * 1000));
            json_object_set_new(message, "method", json_string("agent.sync"));
            json_object_set_new(message, "params", params);

            char *message_data = json_dumps(message, 0);
            size_t message_size = strlen(message_data);
            message_data[message_size++] = '\n';
            data = sdscatlen(data, message_data, message_size);

            json_decref(message);
            free(message_data);
        }
        curr = next;
    }

    if (sdslen(data)) {
        log_trace("send: %s", data);
        send_data(data, sdslen(data));
    }
    sdsfree(data);

    return 0;
}

sds get_clients_info(void)
{
    sds s = sdsempty();
    s = sdscatprintf(s, "%-6s %-21s %-19s %-12s %-12s %-15s %-10s %-14s %-10s %-10s %-6s %-10s\n",
            "id", "addr", "time", "uesr", "worker", "agent", "diff", "pow", "count", "reject", "rate", "hashrate");
    if (!worker_svr)
        return s;
    nw_ses *curr = worker_svr->clt_list_head;
    while (curr) {
        struct client_info *info = curr->privdata;
        if (info->authorized) {
            s = sdscatprintf(s, "%-6"PRIu64" %-21s %-19s %-12s %-12s %-15s %-10d %-14.2f %-10"PRIu64" %-10"PRIu64" %-6.2f %-10s\n",
                    curr->id, nw_sock_human_addr(&curr->peer_addr), strftimestamp(info->connect_time),
                    info->user, info->worker, info->user_agent, info->difficulty, info->share_pow,
                    info->share_valid, info->share_error, (info->share_error / (double)(info->share_valid + info->share_error)) * 100,
                    human_number((info->share_pow * ((uint64_t)1 << 32)) / (current_timestamp() - info->connect_time)));
        }
        curr = curr->next;
    }
    return s;
}

int init_worker(void)
{
    int ret;
    ret = init_worker_svr();
    if (ret < 0)
        return ret;
    ret = init_listener_clt();
    if (ret < 0)
        return ret;

    return 0;
}