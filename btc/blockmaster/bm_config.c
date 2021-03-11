/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/18, create
 */

# include "bm_config.h"
# include "bm_request.h"

struct settings settings;

static int read_blockmaster(json_t *root, const char *key)
{
    int ret = read_cfg_str(root, key, &settings.blockmaster_url, NULL);
    if (ret < 0) {
        return -__LINE__;
    }

    ret = init_blockmaster_config();
    if (ret < 0) {
        return -__LINE__;
    }

    return 0;
}

int read_bitpeer(json_t *root, const char *key)
{
    json_t *node = json_object_get(root, key);
    if (!node || !json_is_array(node)) {
        return -__LINE__;
    }
    settings.bitpeer_count = json_array_size(node);
    settings.bitpeers = malloc(sizeof(char *) * settings.bitpeer_count);
    for (int i = 0; i < settings.bitpeer_count; ++i) {
        json_t *row = json_array_get(node, i);
        if (!json_is_string(row))
            return -__LINE__;
        settings.bitpeers[i] = strdup(json_string_value(row));
    }
    return 0;
}

static int do_load_config(json_t *root)
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
        printf("load svr config fail: %d\n", ret);
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
    ret = load_cfg_coin_rpc(root, "coin", &settings.coin);
    if (ret < 0) {
        printf("load coin config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_real(root, "mempool_timeout", &settings.mempool_timeout, false, 10);
    if (ret < 0) {
        printf("read mempool_timeout fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_str(root, "request_auth", &settings.request_auth, NULL);
    if (ret < 0) {
        printf("read request_auth fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_blockmaster(root, "blockmaster_url");
    if (ret < 0) {
        printf("read blockmaster fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_int(root, "blockmaster_update_interval", &settings.blockmaster_update_interval, false, 30);
    if (ret < 0) {
        printf("read blockmaster_update_interval fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_bitpeer(root, "bitpeer");
    if (ret < 0) {
        printf("read bitpeer fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_real(root, "blockmaster_timeout", &settings.blockmaster_timeout, false, 60);
    if (ret < 0) {
        printf("read blockmaster_timeout fail: %d\n", ret);
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
        return -__LINE__;
    }
    json_decref(root);

    return 0;
}

