/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/03, create
 */

# include "jm_config.h"
# include "ut_base58.h"

struct settings settings;

int read_blockmaster(json_t *root, const char *key)
{
    json_t *node = json_object_get(root, key);
    if (!node || !json_is_array(node)) {
        return -__LINE__;
    }
    settings.blockmaster_count = json_array_size(node);
    settings.blockmasters = malloc(sizeof(char *) * settings.blockmaster_count);
    for (int i = 0; i < settings.blockmaster_count; ++i) {
        json_t *row = json_array_get(node, i);
        if (!json_is_string(row))
            return -__LINE__;
        settings.blockmasters[i] = strdup(json_string_value(row));
    }
    return 0;
}

int read_vcashcoin(json_t *root, const char *key)
{
    settings.vcash_coin = NULL;
    json_t *vcash_obj = json_object_get(root, key);
    if (!vcash_obj)
        return 0;

    settings.vcash_coin = (coin_rpc_cfg *)malloc(sizeof(coin_rpc_cfg));
    return load_cfg_coin_rpc_sub(vcash_obj, settings.vcash_coin);
}

int read_recipient(json_t *root, const char *key, sds *recipient)
{
    char *address;
    int ret = read_cfg_str(root, key, &address, NULL);
    if (ret < 0) {
        printf("read: %s fail: %d\n", key ,ret);
        return -__LINE__;
    }
    *recipient = address2sig(address);
    if (*recipient == NULL) {
        printf("key: %s, invalid address: %s\n", key, address);
        return -__LINE__;
    }

    return 0;
}

int read_recipients(json_t *root, const char *key)
{
    json_t *node = json_object_get(root, key);
    if (!node)
        return 0;
    if (!json_is_array(node))
        return -__LINE__;

    settings.coin_recipient_count = json_array_size(node);
    settings.coin_recipients = (struct coin_recipient *)malloc(sizeof(struct coin_recipient) * settings.coin_recipient_count);
    settings.coin_recipient_percents = 0.0;
    for (int i = 0; i < settings.coin_recipient_count; ++i) {
        json_t *row = json_array_get(node, i);
        if (!json_is_object(row))
            return -__LINE__;

        json_t *address_object = json_object_get(row, "address");
        if(!json_is_string(address_object))
            return -__LINE__;
        json_t *percent_object = json_object_get(row, "percent");
        if(!json_is_real(percent_object))
            return -__LINE__;

        sds address = address2sig(json_string_value(address_object));
        if(address == NULL)
            return -__LINE__;
        double percent = json_real_value(percent_object);
        settings.coin_recipient_percents += percent;
        if(percent < 0.0 || settings.coin_recipient_percents > 1)
            return -__LINE__;
        settings.coin_recipients[i].address = address;
        settings.coin_recipients[i].percent = percent;
    }

    return 0;
}

int read_auxcoin(json_t *root, const char *key)
{
    settings.aux_coin_count = 0;
    settings.aux_coin = NULL;
    json_t *aux_obj = json_object_get(root, key);
    int ret = 0;
    if (aux_obj != NULL) {
         if (json_is_object(aux_obj)) {
            settings.aux_coin_count = 1;
            settings.aux_coin = (coin_rpc_cfg *)malloc(sizeof(coin_rpc_cfg) * settings.aux_coin_count);
            ret = load_cfg_coin_rpc(aux_obj, "aux_coin", settings.aux_coin);
            if (ret < 0) {
                return -__LINE__;
            }
        } else if (json_is_array(aux_obj)) {
            settings.aux_coin_count = json_array_size(aux_obj);
            settings.aux_coin = (coin_rpc_cfg *)malloc(sizeof(coin_rpc_cfg) * settings.aux_coin_count);
            settings.aux_address = (sds *)malloc(sizeof(sds) * settings.aux_coin_count);
            for (int i = 0; i < settings.aux_coin_count; i++) {
                json_t *item = json_array_get(aux_obj, i);
                ret = load_cfg_coin_rpc_sub(item, &settings.aux_coin[i]);
                if (ret < 0) {
                    return -__LINE__;
                }

                json_t *address = json_object_get(item, "address");
                if (address && json_is_string(address)) {
                    settings.aux_address[i] = sdsnew(json_string_value(address));
                } else {
                    settings.aux_address[i] = NULL;
                }
            }
        } else {
            return -__LINE__;
        }
    }
    return 0;
}

int read_rskcoin(json_t *root, const char *key)
{
    settings.rsk_coin = NULL;
    json_t *rsk_obj = json_object_get(root, key);
    if (!rsk_obj)
        return 0;

    settings.rsk_coin = (coin_rpc_cfg *)malloc(sizeof(coin_rpc_cfg));
    return load_cfg_coin_rpc_sub(rsk_obj, settings.rsk_coin);
}

int do_load_config(json_t *root)
{
    int ret;
    ret = load_cfg_process(root, "process", &settings.process);
    if (ret < 0) {
        printf("load process config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_log(root, "log", &settings.log);
    if (ret < 0) {
        printf("load log config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_svr(root, "svr", &settings.svr);
    if (ret < 0) {
        printf("oad svr config fail: %d\n", ret);
        return -__LINE__;
    }
    if (json_object_get(root, "brother") != NULL) {
        settings.has_brother = true;
        ret = load_cfg_rpc_clt(root, "brother", &settings.brother);
        if (ret < 0) {
            printf("oad brother config fail: %d\n", ret);
            return -__LINE__;
        }
    }
    ret = read_blockmaster(root, "blockmaster");
    if (ret < 0) {
        printf("read blockmaster fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_real(root, "blockmaster_timeout", &settings.blockmaster_timeout, false, 60);
    if (ret < 0) {
        printf("read blockmaster_timeout fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_coin_rpc(root, "main_coin", &settings.main_coin);
    if (ret < 0) {
        printf("load main_coin config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_recipient(root, "main_coin_recipient", &settings.main_coin_recipient);
    if (ret < 0) {
        printf("read main_coin_recipient fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_recipients(root, "coin_recipients");
    if (ret < 0) {
        printf("read coin_recipients fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_uint32(root, "main_block_version", &settings.main_block_version, false, 0);
    if (ret < 0) {
        printf("load main_block_version config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_int32(root, "aux_merkle_nonce", &settings.aux_merkle_nonce, true, 0);
    if (ret < 0) {
        printf("read aux_merkle_nonce fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_int32(root, "aux_merkle_size", &settings.aux_merkle_size, true, 8);
    if (ret < 0) {
        printf("read aux_merkle_size fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_int32(root, "aux_job_timeout", &settings.aux_job_timeout, true, 10);
    if (ret < 0) {
        printf("read aux_job_timeout fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_int32(root, "rsk_job_interval", &settings.rsk_job_interval, false, 30);
    if (ret < 0) {
        printf("read rsk_job_interval fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_auxcoin(root, "aux_coin");
    if (ret < 0) {
        printf("load aux_coin config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_rskcoin(root, "rsk_coin");
    if (ret < 0) {
        printf("load rsk_coin config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_vcashcoin(root, "vcash_coin");
    if (ret < 0) {
        printf("load vcash_coin config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_cli_svr(root, "cli", &settings.cli);
    if (ret < 0) {
        printf("load cli config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_alert(root, "alert", &settings.alert);
    if (ret < 0) {
        printf("load alert config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_int(root, "job_rebroadcast_timeout", &settings.job_rebroadcast_timeout, false, 50);
    if (ret < 0) {
        printf("read job_rebroadcast_timeout fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_str(root, "pool_name", &settings.pool_name, "");
    if (ret < 0) {
        printf("read pool_name fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_str(root, "coinbase_message", &settings.coinbase_message, "");
    if (ret < 0) {
        printf("read coinbase_message fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_bool(root, "coinbase_account", &settings.coinbase_account, false, true);
    if (ret < 0) {
        printf("read coinbase_account fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_int(root, "spv_mining_timeout", &settings.spv_mining_timeout, false, 60);
    if (ret < 0) {
        printf("read spv_mining_timeout fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_http_svr(root, "http_svr", &settings.http_svr);
    if (ret < 0) {
        printf("load http svr config fail: %d\n", ret);
        return -__LINE__;
    }

    return 0;
}

int load_config(const char *path)
{
    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    if (root == NULL) {
        printf("json_load_file from: %s fail: %s in line: %d\n", path, error.text, error.line);
        return -__LINE__;
    }
    if (!json_is_object(root)) {
        json_decref(root);
        return -__LINE__;
    }

    int ret = do_load_config(root);
    if (ret < 0) {
        json_decref(root);
        return ret;
    }
    json_decref(root);

    return 0;
}

