/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/03, create
 */

# include "jm_job.h"
# include "jm_aux.h"
# include "jm_rsk.h"
# include "jm_vcash.h"
# include "jm_server.h"
# include "jm_config.h"
# include "jm_broadcast.h"
# include "nw_job.h"
# include "ut_pack.h"
# include "ut_merkle.h"
# include <math.h>

static nw_job *worker;
static nw_timer timer;
static time_t last_update_job;
static time_t last_update_job_start;
static time_t last_shutdown;

static coin_rpc *main_coin;
static sds *aux_hash_bins;
static int main_coin_height;

struct main_outer_info {
    int      height;
    uint32_t version;
    uint32_t curtime;
    uint32_t nbits;
    sds      target;
    sds      prevhash;
};

static struct main_outer_info outer;
static bool spv_mining;
static time_t spv_mining_start;
static sds coinbaseaux_message;

typedef struct aux_meta {
    int merkle_index;
    int chainid;
    sds aux_name;
    sds aux_hash;
    sds aux_target;
} aux_meta;

typedef struct rsk_meta {
    sds rsk_name;
    sds rsk_hash;
    sds rsk_target;
    int mine_height;
} rsk_meta;

typedef struct vcash_meta {
    sds name;
    sds hash;
    sds target;
    int height;
} vcash_meta;

struct job {
    char     job_id[5];
    uint32_t version;
    uint32_t curtime;
    uint32_t nbits;
    uint32_t height;
    sds      prevhash;
    sds      target;
    sds      coinbaseaux;
    sds      coinbase1;
    sds      coinbase2;
    uint32_t tx_count;
    sds      txs;
    sds     *merkle_branch;
    size_t   merkle_branch_count;

    aux_meta *auxes;
    rsk_meta *rsk;
    vcash_meta *vcash;
    struct   job *next;
};

static dict_t *aux_hash_last_dict;
static dict_t *job_dict;
static struct job *curr_job;
static sds coinbase_message;
static sds rsk_hash_last;

static void job_aux_free(aux_meta *auxes, int count)
{
    if (auxes) {
        for (int i = 0; i < count; i++) {
            if (auxes[i].aux_name) {
                sdsfree(auxes[i].aux_name);
            }
            if (auxes[i].aux_hash) {
                sdsfree(auxes[i].aux_hash);
            }
            if (auxes[i].aux_target) {
                sdsfree(auxes[i].aux_target);
            }
        }
        free(auxes);
    }
}

static void job_rsk_free(rsk_meta *rsk)
{
    if (rsk) {
        if (rsk->rsk_name) {
            sdsfree(rsk->rsk_name);
        }
        if (rsk->rsk_hash) {
            sdsfree(rsk->rsk_hash);
        }
        if (rsk->rsk_target) {
            sdsfree(rsk->rsk_target);
        }
        free(rsk);
    }
}

static void job_vcash_free(vcash_meta *vcash)
{
    if (vcash) {
        if (vcash->name) {
            sdsfree(vcash->name);
        }
        if (vcash->hash) {
            sdsfree(vcash->hash);
        }
        if (vcash->target) {
            sdsfree(vcash->target);
        }
        free(vcash);
    }
}

static void job_free(struct job *job)
{
    if (job->prevhash)
        sdsfree(job->prevhash);
    if (job->target)
        sdsfree(job->target);
    if (job->coinbaseaux)
        sdsfree(job->coinbaseaux);
    if (job->coinbase1)
        sdsfree(job->coinbase1);
    if (job->coinbase2)
        sdsfree(job->coinbase2);
    if (job->txs)
        sdsfree(job->txs);
    if (job->merkle_branch) {
        for (size_t i = 0; i < job->merkle_branch_count; ++i) {
            sdsfree(job->merkle_branch[i]);
        }
        free(job->merkle_branch);
    }
    job_aux_free(job->auxes, settings.aux_coin_count);
    job_rsk_free(job->rsk);
    job_vcash_free(job->vcash);
    free(job);
}

static sds get_target(uint32_t nbits, bool reverse)
{
    uint32_t coefficient = nbits & 0x00ffffff;
    uint32_t exponent = nbits >> 24;
    double target = coefficient * pow(2, 8 * (exponent - 3));
    double max = pow(256, 31);
    char target_bin[32] = {0};
    int i = 0;
    for(i = 0; i < 31; i++){
        target_bin[i] = (uint8_t)floor(target / max);
        target -= ((uint8_t)target_bin[i]) * max;
        max = max / 256;
    }
    target_bin[i] = (uint8_t)target;
    if (reverse)
        reverse_mem(target_bin, 32);
    return bin2hex(target_bin, 32);
}

static int get_aux_coin_job(struct job *job)
{
    if (aux_dict == NULL)
        return -__LINE__;
    job->auxes = (aux_meta*)malloc(sizeof(aux_meta) * settings.aux_coin_count);
    if (job->auxes == NULL) {
        log_error("malloc %d auxes failed", settings.aux_coin_count);
        return -__LINE__;
    }
    memset(job->auxes, 0, sizeof(aux_meta) * settings.aux_coin_count);

    dict_iterator *iter = dict_get_iterator(aux_dict);
    if (iter == NULL)
        return -__LINE__;

    dict_entry *entry;
    int index = 0;
    while ((entry = dict_next(iter)) != NULL) {
        sds aux_name = entry->key;
        aux_info *info = entry->val;
        if (info->block == NULL) {
            return -__LINE__;
        }

        job->auxes[index].merkle_index = info->merkle_index;
        job->auxes[index].aux_name = sdsnew(aux_name);
        job->auxes[index].chainid = json_integer_value(json_object_get(info->block, "chainid"));
        job->auxes[index].aux_hash = sdsnew(json_string_value(json_object_get(info->block, "hash")));

        dict_entry *e = dict_find(aux_hash_last_dict, job->auxes[index].aux_name);
        if (e == NULL) {
            dict_add(aux_hash_last_dict, sdsnew(job->auxes[index].aux_name), sdsnew(job->auxes[index].aux_hash));
            e = dict_find(aux_hash_last_dict, job->auxes[index].aux_name);
        }
        sds aux_hash_last = e->val;
        sdsclear(aux_hash_last);
        aux_hash_last = sdscat(aux_hash_last, job->auxes[index].aux_hash);

        sdsclear(aux_hash_bins[info->merkle_index]);
        sds aux_hash_bin = hex2bin(job->auxes[index].aux_hash);
        reverse_mem(aux_hash_bin, sdslen(aux_hash_bin));
        aux_hash_bins[info->merkle_index] = sdscatlen(aux_hash_bins[info->merkle_index], aux_hash_bin, sdslen(aux_hash_bin));
        sdsfree(aux_hash_bin);
        if (sdslen(aux_hash_bins[info->merkle_index]) != 32) {
            log_error("aux hash size: %zu", sdslen(aux_hash_bins[info->merkle_index]));
            return -__LINE__;
        }

        json_t *aux_target_obj = json_object_get(info->block, "_target");
        if (aux_target_obj == NULL) {
            aux_target_obj = json_object_get(info->block, "target");
        }

        json_t *bits_obj = json_object_get(info->block, "bits");

        sds aux_target = NULL;
        if (aux_target_obj && json_is_string(aux_target_obj)) {
            const char *aux_target_str = json_string_value(aux_target_obj);
            log_info("aux_target_str: %s, %s", aux_name, aux_target_str);
            aux_target = sdsnew(aux_target_str);            
        } else if (bits_obj && json_is_string(bits_obj)) {
            const char *bits_str = json_string_value(bits_obj);
            if (strlen(bits_str) == 0) {
                log_info("bits_str is zero len: %s", aux_name);
                return -__LINE__;
            }

            uint32_t nbits_int = strtoul(bits_str, NULL, 16);
            aux_target = get_target(nbits_int, true);
            log_info("aux_target_str: %s, %s", aux_name, aux_target);
        } else {
            log_info("%s, get no target", aux_name);
            return -__LINE__;
        }

        sds aux_target_bin = hex2bin(aux_target);
        if (sdslen(aux_target_bin) != 32) {
            sdsfree(aux_target);
            sdsfree(aux_target_bin);
            return -__LINE__;    
        }
        reverse_mem(aux_target_bin, 32);
        job->auxes[index].aux_target = bin2hex(aux_target_bin, 32);
        sdsfree(aux_target);
        sdsfree(aux_target_bin);

        log_info("aux_name: %s, chainid:%d, aux_hash: %s, aux_target: %s", 
            job->auxes[index].aux_name, job->auxes[index].chainid, job->auxes[index].aux_hash, job->auxes[index].aux_target);
        index++;
    }
    dict_release_iterator(iter);
    
    char buf[100];
    void *p = buf;
    size_t left = sizeof(buf);
    pack_char(&p, &left, 0xfa);
    pack_char(&p, &left, 0xbe);
    pack_char(&p, &left, 'm');
    pack_char(&p, &left, 'm');
   
    int32_t merkle_size = get_merkle_size();
    sds merkle_root_bin = get_merkle_root_custom(aux_hash_bins, merkle_size);
    if (merkle_root_bin == NULL) {
        return -__LINE__;
    }

    if (sdslen(merkle_root_bin) != 32) {
        sdsfree(merkle_root_bin);
        return -__LINE__;
    }

    reverse_mem(merkle_root_bin, 32);
    pack_buf(&p, &left, merkle_root_bin, 32);
    sdsfree(merkle_root_bin);
    pack_uint32_le(&p, &left, merkle_size);
    pack_uint32_le(&p, &left, settings.aux_merkle_nonce);
    sds hex = bin2hex(buf, sizeof(buf) - left);
    job->coinbaseaux = sdscatsds(job->coinbaseaux, hex);
    sdsfree(hex);
    
    return 0;
}

static int pack_output_transaction(void ** p, size_t * left, sds pubkey, enum address_type addr_type, uint64_t reward)
{
    pack_uint64_le(p, left, reward); // reward
    if (addr_type == address_type_p2sh) {
        pack_varint_le(p, left, 23); // p2sh len
    } else {
        pack_varint_le(p, left, 25); // pubkey script len
        pack_char(p, left, 0x76); // OP_DUP
    }
    pack_char(p, left, 0xa9); // OP_HASH160
    pack_char(p, left, 0x14); // Push 20 bytes as data
    pack_buf(p, left, pubkey, sdslen(pubkey)); // PubKey hash
    if (addr_type == address_type_p2sh) {
        pack_char(p, left, 0x87); // OP_EQUAL
    } else {
        pack_char(p, left, 0x88); // OP_EQUALVERIFY
        pack_char(p, left, 0xac); // OP_CHECKSIG
    }
    return 0;
}

static int get_rsk_coin_job(struct job *job)
{
    if (rsk_info->block == NULL)
        return -__LINE__;

    job->rsk = (rsk_meta*)malloc(sizeof(rsk_meta));
    if (job->rsk == NULL) {
        log_error("malloc rsk failed");
        return -__LINE__;
    }
    memset(job->rsk, 0, sizeof(rsk_meta));

    job->rsk->rsk_name = sdsnew(settings.rsk_coin->name);

    if (rsk_info->mine_height < 0) {
        log_info("rsk mine_height invalid, mine_height: %d", rsk_info->mine_height);
        return -__LINE__;
    }
    job->rsk->mine_height = rsk_info->mine_height;

    json_t *rsk_hash_obj = json_object_get(rsk_info->block, "blockHashForMergedMining");
    if (!rsk_hash_obj) {
        log_info("rsk get no hash");
        return -__LINE__;
    }

    const char *rsk_hash = json_string_value(rsk_hash_obj);
    job->rsk->rsk_hash = sdsnew(rsk_hash + 2);
    if (rsk_hash_last) {
        sdsclear(rsk_hash_last);
        rsk_hash_last = sdscatlen(rsk_hash_last, rsk_hash, strlen(rsk_hash));
    } else {
        rsk_hash_last = sdsnew(rsk_hash);
    }

    json_t *rsk_target_obj = json_object_get(rsk_info->block, "target");
    if (!rsk_target_obj) {
        log_info("rsk get no target");
        return -__LINE__;
    }
    job->rsk->rsk_target = sdsnew(json_string_value(rsk_target_obj) + 2);

    return 0;
}

static int get_vcash_coin_job(struct job *job)
{
    if (vcash_info->block == NULL)
        return -__LINE__;

    job->vcash = (vcash_meta *)malloc(sizeof(vcash_meta));
    if (job->vcash == NULL) {
        log_error("malloc vcash failed");
        return -__LINE__;
    }
    memset(job->vcash, 0, sizeof(vcash_meta));

    job->vcash->name = sdsnew(settings.vcash_coin->name);
    job->vcash->height = vcash_info->height;

    json_t *hash_obj = json_object_get(vcash_info->block, "cur_hash");
    if (!hash_obj) {
        log_info("vcash get no hash");
        return -__LINE__;
    }

    const char *hash = json_string_value(hash_obj);
    job->vcash->hash = sdsnew(hash);

    json_t *bits_obj = json_object_get(vcash_info->block, "bits");
    if (!bits_obj) {
        log_info("vcash get no target");
        return -__LINE__;
    }
    job->vcash->target = get_target(json_integer_value(bits_obj), false);
    return 0;
}

static int get_main_coin_job(struct job *job, json_t *r)
{
    if (settings.main_block_version) {
        job->version = settings.main_block_version;
    } else {
        job->version = json_integer_value(json_object_get(r, "version"));
    }

    job->curtime  = json_integer_value(json_object_get(r, "curtime"));
    job->nbits    = strtoul(json_string_value(json_object_get(r, "bits")), NULL, 16);
    job->height   = json_integer_value(json_object_get(r, "height"));
    job->prevhash = sdsnew(json_string_value(json_object_get(r, "previousblockhash")));
    job->target   = sdsnew(json_string_value(json_object_get(r, "target")));
    json_t *txs   = json_object_get(r, "transactions");
    job->tx_count = json_array_size(txs);
    job->txs      = sdsempty();

    sds *nodes = malloc(sizeof(sds) * (job->tx_count + 1));
    for (size_t i = 0; i < job->tx_count; ++i) {
        json_t *tx = json_array_get(txs, i);
        job->txs = sdscat(job->txs, json_string_value(json_object_get(tx, "data")));
        const char *tx_hash = json_string_value(json_object_get(tx, "hash"));
        const char *tx_txid = json_string_value(json_object_get(tx, "txid"));
        if (tx_txid == NULL)
            tx_txid = tx_hash;
        nodes[i] = hex2bin(tx_txid);
        reverse_mem(nodes[i], sdslen(nodes[i]));
    }
    job->merkle_branch = get_merkle_branch(nodes, job->tx_count, &job->merkle_branch_count);
    for (size_t i = 0; i < job->tx_count; ++i) {
        sdsfree(nodes[i]);
    }
    free(nodes);
    if (job->merkle_branch == NULL)
        return -__LINE__;

    char coinbase1[1024];
    void *p = coinbase1;
    size_t left = sizeof(coinbase1);
    pack_uint32_le(&p, &left, 1); // Version
    pack_varint_le(&p, &left, 1); // Number of inputs
    char txin_hash[32] = { 0 };
    pack_buf(&p, &left, txin_hash, sizeof(txin_hash)); // Outpoint TXID
    pack_uint32_le(&p, &left, 0xffffffffu); // Outpoint index number
    job->coinbase1 = bin2hex(coinbase1, sizeof(coinbase1) - left);
    if (job->coinbase1 == NULL)
        return -__LINE__;

    const char *key;
    json_t *value;
    json_t *auxobj = json_object_get(r, "coinbaseaux");
    sdsclear(coinbaseaux_message);
    json_object_foreach(auxobj, key, value) {
        coinbaseaux_message = sdscat(coinbaseaux_message, json_string_value(value));
    }
    job->coinbaseaux = sdscat(job->coinbaseaux, coinbaseaux_message);

    char coinbase2[1024];
    p = coinbase2;
    left = sizeof(coinbase2);
    pack_uint32_le(&p, &left, 0xffffffffu); // input transaction sequence

    int out_transaction_num = settings.coin_recipient_count;
    if (settings.segwit_commitment_enabled) {
        out_transaction_num++;
    }
    bool has_main_reward = false;
    if(settings.coin_recipient_percents < 1) {
        has_main_reward = true;
        out_transaction_num += 1;
    }
    if (job->rsk) {
        out_transaction_num += 1;
    }
    if (job->vcash) {
        out_transaction_num += 1;
    }

    pack_varint_le(&p, &left, out_transaction_num); // output transaction number
    uint64_t coinbasevalue = json_integer_value(json_object_get(r, "coinbasevalue"));
    uint64_t sum = 0;
    uint64_t amount = 0;
    log_trace("coinbasevalue:%ld", coinbasevalue);
    for(int i = 0; i < settings.coin_recipient_count; i++) {
        if(!has_main_reward && i == settings.coin_recipient_count - 1)
            amount = coinbasevalue - sum;
        else
            amount = (uint64_t)floor(coinbasevalue * settings.coin_recipients[i].percent);
        sum += amount;
        pack_output_transaction(&p, &left, settings.coin_recipients[i].address, settings.coin_recipients[i].addr_type, amount);
    }

    if(has_main_reward) {
        amount = coinbasevalue - sum;
        pack_output_transaction(&p, &left, settings.main_coin_recipient, settings.main_coin_recipient_addr_type, amount);
    }

    if (job->rsk) {
        pack_uint64_le(&p, &left, 0);  // reward
        pack_varint_le(&p, &left, 43); // len: 1 + 1 + 9 + 32 
        pack_char(&p, &left, 0x6a);    // OP_RETURN
        pack_varint_le(&p, &left, 41); // len: rsk_flag + hash
        char rsk_flag[9] = {0x52, 0x53, 0x4b, 0x42, 0x4c, 0x4f, 0x43, 0x4b, 0x3a};
        pack_buf(&p, &left, rsk_flag, sizeof(rsk_flag));
        sds hash_bin = hex2bin(job->rsk->rsk_hash);
        pack_buf(&p, &left, hash_bin, sdslen(hash_bin));
        sdsfree(hash_bin);
    }

    if (job->vcash) {
        pack_uint64_le(&p, &left, 0);  // reward
        pack_varint_le(&p, &left, 38); // len: 1 + 1 + 4 + 32 
        pack_char(&p, &left, 0x6a);    // OP_RETURN
        pack_varint_le(&p, &left, 36); // len: MagicNum + hash
        char magic_num[4] = {0xb9, 0xe1, 0x1b, 0x6d};
        pack_buf(&p, &left, magic_num, sizeof(magic_num));
        sds hash_bin = hex2bin(job->vcash->hash);
        pack_buf(&p, &left, hash_bin, sdslen(hash_bin));
        sdsfree(hash_bin);
    }

    if (settings.segwit_commitment_enabled) {
        const char *segwit_commitment = json_string_value(json_object_get(r, "default_witness_commitment"));
        if (!segwit_commitment)
            return -__LINE__;
        sds commitment = hex2bin(segwit_commitment);
        pack_uint64_le(&p, &left, 0);
        pack_varint_le(&p, &left, sdslen(commitment));
        pack_buf(&p, &left, commitment, sdslen(commitment));
        sdsfree(commitment);
    }

    pack_uint32_le(&p, &left, 0); // locktime
    job->coinbase2 = bin2hex(coinbase2, sizeof(coinbase2) - left);

    return 0;
}

static uint64_t get_coinbasevalue(int height)
{
    uint64_t coinbasevalue = 5000000000ull;
    int half_interval = 210000;
    while (height > half_interval) {
        coinbasevalue /= 2;
        height -= half_interval;
    }
    return coinbasevalue;
}

uint32_t get_current_height()
{
    return main_coin_height;
}

static int get_main_coin_job_empty(struct job *job)
{
    if (settings.main_block_version) {
        job->version = settings.main_block_version;
    } else {
        job->version = outer.version;
    }

    job->curtime  = outer.curtime;
    job->nbits    = outer.nbits;
    job->height   = outer.height + 1;
    job->prevhash = sdsnew(outer.prevhash);
    job->target   = sdsnew(outer.target);
    job->tx_count = 0;
    job->txs      = sdsempty();
    job->merkle_branch = NULL;
    job->merkle_branch_count = 0;

    if (sdslen(coinbaseaux_message)) {
        job->coinbaseaux = sdscat(job->coinbaseaux, coinbaseaux_message);
    }

    char coinbase1[1024];
    void *p = coinbase1;
    size_t left = sizeof(coinbase1);
    pack_uint32_le(&p, &left, 1); // Version
    pack_varint_le(&p, &left, 1); // Number of inputs
    char txin_hash[32] = { 0 };
    pack_buf(&p, &left, txin_hash, sizeof(txin_hash)); // Outpoint TXID
    pack_uint32_le(&p, &left, 0xffffffffu); // Outpoint index number
    job->coinbase1 = bin2hex(coinbase1, sizeof(coinbase1) - left);

    char coinbase2[1024];
    p = coinbase2;
    left = sizeof(coinbase2);
    pack_uint32_le(&p, &left, 0xffffffffu); // input transaction sequence

    int out_transaction_num = settings.coin_recipient_count;
    bool has_main_reward = false;
    if(settings.coin_recipient_percents < 1) {
        has_main_reward = true;
        out_transaction_num += 1;
    }
    if (job->rsk) {
        out_transaction_num += 1;
    }
    if (job->vcash) {
        out_transaction_num += 1;
    }


    pack_varint_le(&p, &left, out_transaction_num); // output transaction number
    uint64_t coinbasevalue = get_coinbasevalue(job->height);
    uint64_t sum = 0;
    uint64_t amount = 0;
    for(int i = 0; i < settings.coin_recipient_count; i++) {
        if(!has_main_reward && i == settings.coin_recipient_count - 1)
            amount = coinbasevalue - sum;
        else
            amount = (uint64_t)floor(coinbasevalue * settings.coin_recipients[i].percent);
        sum += amount;
        pack_output_transaction(&p, &left, settings.coin_recipients[i].address, settings.coin_recipients[i].addr_type, amount);
    }
    if (job->rsk) {
        pack_uint64_le(&p, &left, 0);  // reward
        pack_varint_le(&p, &left, 43); // len: 1 + 1 + 9 + 32 
        pack_char(&p, &left, 0x6a);    // OP_RETURN
        pack_varint_le(&p, &left, 41); // len: rsk_flag + hash
        char rsk_flag[9] = {0x52, 0x53, 0x4b, 0x42, 0x4c, 0x4f, 0x43, 0x4b, 0x3a};
        pack_buf(&p, &left, rsk_flag, sizeof(rsk_flag));
        sds hash_bin = hex2bin(job->rsk->rsk_hash);
        pack_buf(&p, &left, hash_bin, sdslen(hash_bin));
        sdsfree(hash_bin);
    }
    if (job->vcash) {
        pack_uint64_le(&p, &left, 0);  // reward
        pack_varint_le(&p, &left, 38); // len: 1 + 1 + 4 + 32 
        pack_char(&p, &left, 0x6a);    // OP_RETURN
        pack_varint_le(&p, &left, 36); // len: MagicNum + hash
        char magic_num[4] = {0xb9, 0xe1, 0x1b, 0x6d};
        pack_buf(&p, &left, magic_num, sizeof(magic_num));
        sds hash_bin = hex2bin(job->vcash->hash);
        pack_buf(&p, &left, hash_bin, sdslen(hash_bin));
        sdsfree(hash_bin);
    }

    if(has_main_reward) {
        amount = coinbasevalue - sum;
        pack_output_transaction(&p, &left, settings.main_coin_recipient, settings.main_coin_recipient_addr_type, amount);
    }
    pack_uint32_le(&p, &left, 0); // locktime
    job->coinbase2 = bin2hex(coinbase2, sizeof(coinbase2) - left);

    return 0;
}

static int get_serialized_job(struct job *job, rpc_pkg *pkg, bool clean)
{
    if (job == NULL)
        return -__LINE__;

    memset(pkg, 0, sizeof(rpc_pkg));
    pkg->command = CMD_UPDATE_JOB;
    pkg->pkg_type = RPC_PKG_TYPE_PUSH;

    json_t *r = json_object();
    json_object_set_new(r, "job_id", json_string(job->job_id));
    json_object_set_new(r, "version", json_integer(job->version));
    json_object_set_new(r, "curtime", json_integer(job->curtime));
    json_object_set_new(r, "nbits", json_integer(job->nbits));
    json_object_set_new(r, "height", json_integer(job->height));
    json_object_set_new(r, "prevhash", json_string(job->prevhash));
    json_object_set_new(r, "target", json_string(job->target));
    json_object_set_new(r, "pool_name", json_string(settings.pool_name));
    json_object_set_new(r, "coinbase_message", json_string(coinbase_message));
    json_object_set_new(r, "coinbase_account", json_boolean(settings.coinbase_account));
    json_object_set_new(r, "coinbaseaux", json_string(job->coinbaseaux));
    json_object_set_new(r, "coinbase1", json_string(job->coinbase1));
    json_object_set_new(r, "coinbase2", json_string(job->coinbase2));
    json_object_set_new(r, "clean_jobs", clean ? json_true() : json_false());
    json_object_set_new(r, "main_name", json_string(main_coin->name));
    json_object_set_new(r, "aux_target", json_string(""));

    json_t *merkle_branch = json_array();
    for (size_t i = 0; i < job->merkle_branch_count; ++i) {
        sds hex = bin2hex(job->merkle_branch[i], sdslen(job->merkle_branch[i]));
        json_array_append_new(merkle_branch, json_string(hex));
        sdsfree(hex);
    }
    json_object_set_new(r, "merkle_branch", merkle_branch);

    json_t *aux_arr = json_array();
    if (settings.aux_coin_count > 0 && job->auxes) {
        for (int i = 0; i < settings.aux_coin_count; i++) {
            json_t *aux_obj = json_object();
            json_object_set_new(aux_obj, "aux_name", json_string(job->auxes[i].aux_name));
            json_object_set_new(aux_obj, "aux_hash", json_string(job->auxes[i].aux_hash));
            json_object_set_new(aux_obj, "aux_target", json_string(job->auxes[i].aux_target));
            json_array_append_new(aux_arr, aux_obj);
        }
    }
    if (job->rsk) {
        json_t *rsk_obj = json_object();
        json_object_set_new(rsk_obj, "aux_name", json_string(job->rsk->rsk_name));
        char buf[16];
        snprintf(buf, sizeof(buf), "%0x", job->rsk->mine_height);
        json_object_set_new(rsk_obj, "aux_hash", json_string(buf));
        json_object_set_new(rsk_obj, "aux_target", json_string(job->rsk->rsk_target));
        json_array_append_new(aux_arr, rsk_obj);
    }
    if (job->vcash) {
        json_t *vcash_obj = json_object();
        json_object_set_new(vcash_obj, "aux_name", json_string(job->vcash->name));
        json_object_set_new(vcash_obj, "aux_hash", json_string(job->vcash->hash));
        json_object_set_new(vcash_obj, "aux_target", json_string(job->vcash->target));
        json_array_append_new(aux_arr, vcash_obj);
    }
    json_object_set_new(r, "auxes", aux_arr);

    char *body = json_dumps(r, 0);
    if (body == NULL) {
        log_error("json_dumps fail");
        json_decref(r);
        return -__LINE__;
    }
    log_info("serialized job: %s", body);

    pkg->body_size = strlen(body);
    pkg->body = body;
    json_decref(r);

    return 0;
}

static int broadcast_curr_job(void)
{
    rpc_pkg pkg;
    int ret = get_serialized_job(curr_job, &pkg, job_dict->used == 1);
    if (ret < 0) {
        log_error("get serialized job fail: %d", ret);
        return -__LINE__;
    }
    broadcast_msg(&pkg);
    free(pkg.body);
    return 0;
}

static void get_job_id(struct job *job)
{
    static uint16_t job_id;
    uint16_t id = job_id++;
    if (id == 0)
        id = job_id++;
    snprintf(job->job_id, sizeof(job->job_id), "%x", id);
}

static int update_job(json_t *template)
{
    struct job *job = malloc(sizeof(struct job));
    memset(job, 0, sizeof(struct job));
    job->coinbaseaux = sdsempty();
    get_job_id(job);

    int ret;
    if (settings.aux_coin_count > 0) {
        ret = get_aux_coin_job(job);
        if (ret < 0) {
            job_aux_free(job->auxes, settings.aux_coin_count);
            job->auxes = NULL;
            log_error("get_aux_coin_job fail: %d", ret);
        }
    }

    if (settings.rsk_coin) {
        ret = get_rsk_coin_job(job);
        if (ret < 0) {
            job_rsk_free(job->rsk);
            job->rsk = NULL;
            log_error("get_rsk_coin_job fail: %d", ret);
        }
    }

    if (settings.vcash_coin) {
        ret = get_vcash_coin_job(job);
        if (ret < 0) {
            job_vcash_free(job->vcash);
            job->vcash = NULL;
            log_error("get_vcash_coin_job fail: %d", ret);
        }
    }

    ret = get_main_coin_job(job, template);
    if (ret < 0) {
        job_free(job);
        log_error("get_main_coin_job fail: %d", ret);
        return -__LINE__;
    }

    sds job_id = sdsnew(job->job_id);
    dict_add(job_dict, job_id, job);
    curr_job = job;

    broadcast_curr_job();
    last_update_job = time(NULL);
    log_info("broadcast job: %s, target height: %d, main height: %d, outer height: %d, clean: %s",
            job->job_id, job->height, main_coin_height, outer.height, job_dict->used == 1 ? "true" : "false");

    return 0;
}

static int update_job_empty(void)
{
    struct job *job = malloc(sizeof(struct job));
    memset(job, 0, sizeof(struct job));
    job->coinbaseaux = sdsempty();
    get_job_id(job);

    int ret;
    if (settings.aux_coin_count > 0) {
        ret = get_aux_coin_job(job);
        if (ret < 0) {
            job_aux_free(job->auxes, settings.aux_coin_count);
            job->auxes = NULL;
            log_error("get_aux_coin_job fail: %d", ret);
        }
    }

    if (settings.rsk_coin) {
        ret = get_rsk_coin_job(job);
        if (ret < 0) {
            job_rsk_free(job->rsk);
            job->rsk = NULL;
            log_error("get_rsk_coin_job fail: %d", ret);
        }
    }

    ret = get_main_coin_job_empty(job);
    if (ret < 0) {
        job_free(job);
        log_error("get_main_coin_job_empty fail: %d", ret);
        return -__LINE__;
    }

    sds job_id = sdsnew(job->job_id);
    dict_add(job_dict, job_id, job);
    curr_job = job;

    broadcast_curr_job();
    last_update_job = time(NULL);
    log_info("broadcast job: %s, target height: %d, main height: %d, outer height: %d, clean: %s",
            job->job_id, job->height, main_coin_height, outer.height, job_dict->used == 1 ? "true" : "false");

    return 0;
}

static void clear_job(void)
{
    dict_clear(job_dict);
    curr_job = NULL;
    log_info("clear job");
}

static int req_getblockcount(void)
{
    json_t *message = json_object();
    json_object_set_new(message, "timeout", json_real(10.0));
    json_object_set_new(message, "method", json_string("getblockcount"));
    json_object_set_new(message, "params", json_array());

    int ret = nw_job_add(worker, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail: %d", ret);
        return -__LINE__;
    }

    return 0;
}

static int req_getblocktemplate(bool clean)
{
    json_t *params = json_array();
    json_t *record = json_object();
    json_t *rules = json_array();
    json_array_append_new(rules, json_string("segwit"));
    json_object_set_new(record, "rules", rules);
    json_array_append_new(params, record);

    json_t *message = json_object();
    json_object_set_new(message, "timeout", json_real(10.0));
    json_object_set_new(message, "method", json_string("getblocktemplate"));
    json_object_set_new(message, "params", params);
    json_object_set_new(message, "clean", json_boolean(clean));

    log_debug("send getblocktemplate request, clean: %s", clean ? "true" : "false");
    int ret = nw_job_add(worker, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail: %d", ret);
        return -__LINE__;
    }

    return 0;
}

static void on_timer(nw_timer *timer, void *privdata)
{
    req_getblockcount();

    time_t now = time(NULL);
    if (spv_mining && (now - spv_mining_start) >= settings.spv_mining_timeout) {
        log_fatal("spv mining timeout");
        req_getblocktemplate(true);
        spv_mining = false;
        memset(&outer, 0, sizeof(outer));
        return;
    }

    if ((now - last_update_job_start) >= 10 && (now - last_update_job) >= settings.job_rebroadcast_timeout) {
        last_update_job_start = now;
        if (!spv_mining) {
            log_info("update main job");
            req_getblocktemplate(false);
        } else {
            int ret = update_job_empty();
            if (ret < 0) {
                log_error("update job empty fail: %d", ret);
                return;
            }
        }
    }

    if ((now - last_update_job) >= 600 && (now - last_shutdown) >= 60) {
        log_info("last_update_job: %ld, last_shutdown: %ld, shutdown server", last_update_job, last_shutdown);
        last_shutdown = now;
        clear_job();
        close_all_connection();
    }
}

static void *on_worker_init(void)
{
    return coin_rpc_create(&settings.main_coin);
}
static void on_worker(nw_job_entry *entry, void *privdata)
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

static int on_blockcount_update(int blockcount)
{
    if (blockcount != main_coin_height && blockcount >= outer.height) {
        log_info("main blockchain switch to new block, height: %d", blockcount);
        if (spv_mining && blockcount == outer.height) {
            req_getblocktemplate(false);
        } else {
            req_getblocktemplate(true);
        }
        main_coin_height = blockcount;
        spv_mining = false;
        return 0;
    } else if (blockcount != main_coin_height) {
        log_info("main height update to: %d", blockcount);
        main_coin_height = blockcount;
    }

    return 0;
}

static void on_worker_finish(nw_job_entry *entry)
{
    json_t *message = entry->request;
    const char *method = json_string_value(json_object_get(message, "method"));
    json_t *reply = entry->reply;
    if (reply == NULL) {
        if (strcmp(method, "getblocktemplate") == 0) {
            log_fatal("getblocktemplate fail");
        } else {
            log_error("rpc %s fail", method);
        }
        return;
    }

    if (strcmp(method, "getblockcount") == 0) {
        int ret = on_blockcount_update(json_integer_value(reply));
        if (ret < 0) {
            log_error("on_blockcount_update fail: %d", ret);
        }
    } else if (strcmp(method, "submitblock") == 0) {
        if (json_is_null(reply)) {
            log_info("submitblock success");
        } else {
            const char *error = json_string_value(reply);
            if (error == NULL)
                error = "null";
            if (strcmp(error, "duplicate") == 0) {
                log_error("submitblock fail: %s", error);
            } else {
                log_fatal("submitblock fail: %s", error);
            }
        }
    } else if (strcmp(method, "getblocktemplate") == 0) {
        bool clean = json_boolean_value(json_object_get(message, "clean"));
        if (clean) {
            clear_job();
        } else if (curr_job && json_integer_value(json_object_get(reply, "height")) != curr_job->height) {
            return;
        }
        int ret = update_job(reply);
        if (ret < 0) {
            char *dumps = json_dumps(reply, 0);
            log_fatal("update_job fail: %s", dumps);
            free(dumps);
        }
    }
}

static void on_worker_cleanup(nw_job_entry *entry)
{
    if (entry->request)
        json_decref(entry->request);
    if (entry->reply)
        json_decref(entry->reply);
}
static void on_worker_release(void *privdata)
{
    coin_rpc_release(privdata);
}

static uint32_t aux_hash_last_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sdslen((sds)key));
}

static int aux_hash_last_dict_key_compare(const void *key1, const void *key2)
{
    return sdscmp((sds)key1, (sds)key2);
}

static void aux_hash_last_dict_key_free(void *key)
{
    sdsfree((sds)key);
}

static void aux_hash_last_dict_val_free(void *val)
{
    sdsfree((sds)val);
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

static int rpc_getblockcount(coin_rpc *coin)
{
    double start = current_timestamp();
    json_t *r = coin_rpc_cmd(coin, 1, "getblockcount", NULL);
    double end = current_timestamp();
    log_trace("name: %s getblockcount cost time: %f", coin->name, end - start);
    if (r == NULL) {
        log_error("name: %s rpc getblockcount fail", coin->name);
        return -__LINE__;
    }
    int blockcount = json_integer_value(r);
    json_decref(r);
    return blockcount;
}

static json_t *rpc_getblocktemplate(coin_rpc *coin)
{
    json_t *params = json_array();
    json_t *record = json_object();
    json_t *rules = json_array();
    json_array_append_new(rules, json_string("segwit"));
    json_object_set_new(record, "rules", rules);
    json_array_append_new(params, record);

    double start = current_timestamp();
    json_t *r = coin_rpc_cmd(coin, 10, "getblocktemplate", params);
    json_decref(params);
    double end = current_timestamp();
    log_debug("coin: %s getblocktemplate cost time: %f", coin->name, end - start);
    if (r == NULL) {
        log_fatal("coin: %s getblocktemplate fail", coin->name);
        return NULL;
    }
    return r;
}

static int do_update_job(void)
{
    json_t *r = rpc_getblocktemplate(main_coin);
    if (r == NULL)
        return -__LINE__;
    int ret = update_job(r);
    if (ret < 0) {
        json_decref(r);
        return -__LINE__;
    }
    json_decref(r);
    return 0;
}

static bool check_new_aux()
{
    dict_iterator *iter = dict_get_iterator(aux_dict);
    if (iter == NULL)
        return false;

    bool new_aux = false;
    dict_entry *entry;
    while ((entry = dict_next(iter)) != NULL) {
        aux_info *info = entry->val;
        if (info->block == NULL) {
            break;
        }

        sds aux_name = entry->key;
        dict_entry *e = dict_find(aux_hash_last_dict, aux_name);
        if (e == NULL) {
            break; 
        }

        const char *aux_hash = json_string_value(json_object_get(info->block, "hash"));
        if (strcmp(aux_hash, e->val) != 0) {
            new_aux = true;
            break;
        }
    }
    dict_release_iterator(iter);
    return new_aux;
}

static bool check_new_rsk()
{
    if (rsk_hash_last && rsk_info && rsk_info->block) {
        const char *rsk_hash = json_string_value(json_object_get(rsk_info->block, "blockHashForMergedMining"));
        if (rsk_hash && strcmp(rsk_hash, rsk_hash_last) != 0) {
            return true;
        }
    }
    return false;
}

int init_job(void)
{
    main_coin = coin_rpc_create(&settings.main_coin);
    if (main_coin == NULL)
        return -__LINE__;
    main_coin_height = rpc_getblockcount(main_coin);
    if (main_coin_height < 0)
        return -__LINE__;

    nw_job_type type_worker;
    memset(&type_worker, 0, sizeof(type_worker));
    type_worker.on_init = on_worker_init;
    type_worker.on_job = on_worker;
    type_worker.on_finish = on_worker_finish;
    type_worker.on_cleanup = on_worker_cleanup;
    type_worker.on_release = on_worker_release;

    worker = nw_job_create(&type_worker, 2);
    if (worker == NULL)
        return -__LINE__;

    dict_types type_job;
    memset(&type_job, 0, sizeof(type_job));
    type_job.hash_function  = job_dict_hash_func;
    type_job.key_compare    = job_dict_key_compare;
    type_job.key_destructor = job_dict_key_free;
    type_job.val_destructor = job_dict_val_free;

    job_dict = dict_create(&type_job, 64);
    if (job_dict == NULL)
        return -__LINE__;

    dict_types type_aux_last_hash;
    memset(&type_aux_last_hash, 0, sizeof(type_aux_last_hash));
    type_aux_last_hash.hash_function  = aux_hash_last_dict_hash_func;
    type_aux_last_hash.key_compare    = aux_hash_last_dict_key_compare;
    type_aux_last_hash.key_destructor = aux_hash_last_dict_key_free;
    type_aux_last_hash.val_destructor = aux_hash_last_dict_val_free;

    aux_hash_last_dict = dict_create(&type_aux_last_hash, 64);
    if (aux_hash_last_dict == NULL)
        return -__LINE__;

    int merkle_size = get_merkle_size();
    aux_hash_bins = (sds*)malloc(sizeof(sds) * merkle_size);
    for (int i = 0; i < merkle_size; i++) {
        aux_hash_bins[i] = sdsnewlen(NULL, 32);
    }

    coinbase_message = sdsnew(settings.coinbase_message);
    coinbaseaux_message = sdsempty();
    ERR_RET(do_update_job());

    nw_timer_set(&timer, 1, true, on_timer, NULL);
    nw_timer_start(&timer);

    return 0;
}

int send_curr_job(nw_ses *ses)
{
    rpc_pkg pkg;
    int ret = get_serialized_job(curr_job, &pkg, true);
    if (ret < 0) {
        log_error("get serialized job fail: %d", ret);
        return -__LINE__;
    }
    rpc_send(ses, &pkg);
    free(pkg.body);

    return 0;
}

int set_coinbase_message(sds msg)
{
    log_info("update coinbase message from: %s to: %s", coinbase_message, msg);
    sdsclear(coinbase_message);
    coinbase_message = sdscatsds(coinbase_message, msg);
    return 0;
}

sds get_coinbase_message(void)
{
    return coinbase_message;
}

int clear_coinbase_message(void)
{
    log_info("clear coinbase message: %s", coinbase_message);
    sdsclear(coinbase_message);
    return 0;
}

int on_main_blocknotify(void)
{
    req_getblockcount();
    return 0;
}

int on_height_update(int height, uint32_t curtime, uint32_t nbits, const char *target, const char *prevhash)
{
    if (outer.height < height && height == (main_coin_height + 1)) {
        if (curr_job == NULL)
            return -__LINE__;
        outer.height = height;
        outer.version = curr_job->version;
        outer.curtime = curtime;
        if (nbits) {
            outer.nbits = nbits;
        } else {
            outer.nbits = curr_job->nbits;
        }
        if (outer.target) {
            sdsfree(outer.target);
        }
        if (target) {
            outer.target = sdsnew(target);
        } else {
            outer.target = sdsnew(curr_job->target);
        }
        if (outer.prevhash)
            sdsfree(outer.prevhash);
        outer.prevhash = sdsnew(prevhash);
        log_info("outer height update to: height: %d, version: %u, curtime; %u, nbits: %#x, target: %s, prevhash: %s", 
                outer.height, outer.version, outer.curtime, outer.nbits, outer.target, outer.prevhash);

        if (spv_mining) {
            clear_job();
            int ret = update_job_empty();
            if (ret < 0) {
                log_error("update job empty fail: %d", ret);
                return -__LINE__;
            }
            spv_mining_start = time(NULL);
            return 0;
        }
    }

    if (outer.height == (main_coin_height + 1) && !spv_mining) {
        log_info("start mining empty block, local height: %d, outer height: %d", main_coin_height, outer.height);
        clear_job();
        int ret = update_job_empty();
        if (ret < 0) {
            log_error("update job empty fail: %d", ret);
            return -__LINE__;
        }
        spv_mining = true;
        spv_mining_start = time(NULL);
    }

    return 0;
}

int on_aux_update(void)
{
    if (!check_new_aux()) {
        log_info("have no new aux");
        return 0;
    }

    if (!spv_mining) {
        log_info("update aux job");
        req_getblocktemplate(false);
    } else {
        log_info("update aux job spv");
        int ret = update_job_empty();
        if (ret < 0) {
            log_error("update job empty fail: %d", ret);
            return -__LINE__;
        }
    }

    return 0;
}

int on_rsk_update(void)
{
    if (!check_new_rsk()) {
        log_info("have no new rsk");
        return 0;
    }

    if (!spv_mining) {
        log_info("update rsk job");
        req_getblocktemplate(false);
    } else {
        log_info("update rsk job spv");
        int ret = update_job_empty();
        if (ret < 0) {
            log_error("update job empty fail: %d", ret);
            return -__LINE__;
        }
    }

    return 0;
}

int on_vcash_update(void)
{
    if (!spv_mining) {
        log_info("update vcash job");
        req_getblocktemplate(false);
    } else {
        log_info("update vcash job spv");
        int ret = update_job_empty();
        if (ret < 0) {
            log_error("update job empty fail: %d", ret);
            return -__LINE__;
        }
    }

    return 0;
}

static int submit_main_block(const char *block_hash, const char *block)
{
    json_t *params = json_array();
    json_array_append_new(params, json_string(block));

    json_t *message = json_object();
    json_object_set_new(message, "timeout", json_real(10.0));
    json_object_set_new(message, "method", json_string("submitblock"));
    json_object_set_new(message, "params", params);

    log_info("submitblock: %s", block_hash);
    int ret = nw_job_add(worker, 0, message);
    if (ret < 0) {
        log_error("nw_job_add fail: %d", ret);
        return -__LINE__;
    }

    return 0;
}

static void broadcast_block(sds block)
{
    sds block_raw = hex2bin(block);
    if (block_raw == NULL)
        return;

    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.command = CMD_SUBMIT_BLOCK;
    pkg.pkg_type = RPC_PKG_TYPE_PUSH;
    pkg.body = block_raw;
    pkg.body_size = sdslen(block_raw);

    broadcast_block_msg(&pkg);
    log_info("broadcast block success");
    sdsfree(block_raw);
}

int on_found_block_main(sds job_id, sds block_head, sds coinbase)
{
    struct dict_entry *entry = dict_find(job_dict, job_id);
    if (entry == NULL) {
       log_error("find job: %s fail", job_id);
        return -__LINE__;
    }
    struct job *job = entry->val;

    char buf[10];
    void *p = buf;
    size_t left = sizeof(buf);
    pack_varint_le(&p, &left, 1 + job->tx_count);
    sds tx_count = bin2hex(buf, sizeof(buf) - left);

    sds block = sdsempty();
    block = sdscatsds(block, block_head); // block head
    block = sdscatsds(block, tx_count); // tx count
    block = sdscatsds(block, coinbase); // coinbase tx
    block = sdscatsds(block, job->txs); // txs
    sdsfree(tx_count);

    sds block_head_bin = hex2bin(block_head);
    if (block_head_bin == NULL)
        return -__LINE__;
    char hash[32];
    sha256d(block_head_bin, sdslen(block_head_bin), hash);
    reverse_mem(hash, sizeof(hash));
    sds block_hash = bin2hex(hash, sizeof(hash));
    sdsfree(block_head_bin);

    broadcast_block(block);
    submit_main_block(block_hash, block);

    sds block_bin = hex2bin(block);
    sds block_dump = hexdump(block_bin, sdslen(block_bin));
    log_vip("found main blockchain block: %s, data: \n%s", block_hash, block_dump);
    sdsfree(block_bin);
    sdsfree(block_dump);

    sdsfree(block_hash);
    sdsfree(block);

    return 0;
}

static sds get_rsk_merkle_hashes(sds coinbase_hash, sds *merkle_branch, int merkle_branch_count)
{
    sds merkle_hashes_hex = sdsdup(coinbase_hash);
    for (int i = 0; i < merkle_branch_count; i++) {
        merkle_hashes_hex = sdscat(merkle_hashes_hex, " ");
        sds merkle_branch_hex = bin2hex(merkle_branch[i], sdslen(merkle_branch[i]));
        merkle_hashes_hex = sdscatsds(merkle_hashes_hex, merkle_branch_hex);
        sdsfree(merkle_branch_hex);
    }

    return merkle_hashes_hex;
}

static sds get_vcash_merkle_hashes(sds *merkle_branch, int merkle_branch_count)
{
    sds merkle_hashes_hex = sdsempty();
    for (int i = 0; i < merkle_branch_count; i++) {
        sds branch_reverse = sdsdup(merkle_branch[i]);
        reverse_mem(branch_reverse, sdslen(branch_reverse));
        sds merkle_branch_hex = bin2hex(branch_reverse, sdslen(branch_reverse));
        merkle_hashes_hex = sdscatsds(merkle_hashes_hex, merkle_branch_hex);
        sdsfree(merkle_branch_hex);
        sdsfree(branch_reverse);
    }
    return merkle_hashes_hex;
}

int on_found_block_aux(sds job_id, sds block_head, sds coinbase, const char *aux_name)
{
    struct dict_entry *entry = dict_find(job_dict, job_id);
    if (entry == NULL) {
       log_error("find job: %s fail", job_id);
        return -__LINE__;
    }
    struct job *job = entry->val;

    if (job->rsk && strcmp(aux_name, job->rsk->rsk_name) == 0) {
        char coinbase_hash[32];
        sds coinbase_hash_bin = hex2bin(coinbase);
        sha256d(coinbase_hash_bin, sdslen(coinbase_hash_bin), coinbase_hash);
        sds coinbase_hash_hex = bin2hex(coinbase_hash, sizeof(coinbase_hash));
        sds merkle_hashes = get_rsk_merkle_hashes(coinbase_hash_hex, job->merkle_branch, job->merkle_branch_count);

        log_vip("found rsk blockchain block, hash: %s", job->rsk->rsk_hash);
        submit_rsk_block(job->rsk->rsk_hash, block_head, coinbase, merkle_hashes, job->tx_count);
        sdsfree(coinbase_hash_bin);
        sdsfree(coinbase_hash_hex);
        sdsfree(merkle_hashes);
        return 0;
    }

    if (job->vcash && strcmp(aux_name, job->vcash->name) == 0) {
        log_vip("found vcash blockchain block, hash: %s", job->vcash->hash);
        sds merkle_hashes = get_vcash_merkle_hashes(job->merkle_branch, job->merkle_branch_count);
        submit_vcash_block(job->vcash->hash, block_head, coinbase, merkle_hashes);
        sdsfree(merkle_hashes);
        return 0;
    }

    char buf[2048];
    void *p = buf;
    size_t left = sizeof(buf);
    pack_varint_le(&p, &left, job->merkle_branch_count);
    for (size_t i = 0; i < job->merkle_branch_count; ++i) {
        pack_buf(&p, &left, job->merkle_branch[i], sdslen(job->merkle_branch[i]));
    }
    pack_uint32_le(&p, &left, 0);
    sds coinbase_branch = bin2hex(buf, sizeof(buf) - left);

    sds block_head_bin = hex2bin(block_head);
    if (block_head_bin == NULL) {
        sdsfree(coinbase_branch);
        return -__LINE__;
    }
    char hash[32];
    sha256d(block_head_bin, sdslen(block_head_bin), hash);
    sds block_hash = bin2hex(hash, sizeof(hash));
    sdsfree(block_head_bin);

    int merkle_index = -1;
    sds aux_hash;
    for (int i = 0; i < settings.aux_coin_count; i++) {
        sdsclear(aux_hash_bins[job->auxes[i].merkle_index]);
        sds aux_hash_bin = hex2bin(job->auxes[i].aux_hash);
        reverse_mem(aux_hash_bin, sdslen(aux_hash_bin));
        aux_hash_bins[job->auxes[i].merkle_index] = sdscatlen(aux_hash_bins[job->auxes[i].merkle_index], aux_hash_bin, sdslen(aux_hash_bin));
        sdsfree(aux_hash_bin);
        if (strcmp(job->auxes[i].aux_name, aux_name) == 0) {
            merkle_index = job->auxes[i].merkle_index;
            aux_hash = job->auxes[i].aux_hash; 
        }
    }
    if (merkle_index < 0) {
        log_error("can not find merkle_index");
        sdsfree(block_hash);
        return -__LINE__;
    }

    int branch_count = 0;
    int merkle_size = get_merkle_size();
    sds *merkle_branch = get_merkle_branch_custom(aux_hash_bins, merkle_size, merkle_index, &branch_count);
    if (merkle_branch == NULL) {
        log_error("can not get merkle branch");
        sdsfree(block_hash);
        return -__LINE__;
    }
    p = buf;
    left = sizeof(buf);
    pack_varint_le(&p, &left, branch_count);
    for (size_t i = 0; i < branch_count; ++i) {
        pack_buf(&p, &left, merkle_branch[i], sdslen(merkle_branch[i]));
        sdsfree(merkle_branch[i]);
    }
    free(merkle_branch);
    pack_uint32_le(&p, &left, merkle_index);
    sds chain_branch = bin2hex(buf, sizeof(buf) - left);

    sds auxpow = sdsempty();
    auxpow = sdscat(auxpow, coinbase);
    auxpow = sdscat(auxpow, block_hash);
    auxpow = sdscat(auxpow, coinbase_branch);
    auxpow = sdscat(auxpow, chain_branch);
    auxpow = sdscat(auxpow, block_head);
    sdsfree(block_hash);
    sdsfree(coinbase_branch);
    sdsfree(chain_branch);

    log_vip("found %s aux blockchain block, hash: %s, auxpow: %s", aux_name, aux_hash, auxpow);
    submit_aux_block(aux_name, aux_hash, auxpow);
    sdsfree(auxpow);

    return 0;
}
