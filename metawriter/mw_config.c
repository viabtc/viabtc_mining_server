/*
 * Description: 
 *     History: yang@haipo.me, 2016/12/03, create
 */

# include "mw_config.h"

struct settings settings;

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
        printf("load svr config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_cli_svr(root, "cli", &settings.cli);
    if (ret < 0) {
        printf("load cli config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_svr(root, "monitor", &settings.monitor);
    if (ret < 0) {
        printf("load monitor config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_alert(root, "alert", &settings.alert);
    if (ret < 0) {
        printf("load alert config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_redis(root, "redis", &settings.redis);
    if (ret < 0) {
        printf("load redis config fail: %d\n", ret);
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
    ret = read_cfg_int(root, "key_expire", &settings.key_expire, false, 3600);
    if (ret < 0) {
        printf("load key_expire config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_int(root, "dup_timeout", &settings.dup_timeout, false, 3600);
    if (ret < 0) {
        printf("load dup_timeout config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_str(root, "trust_file", &settings.trust_file, NULL);
    if (ret < 0) {
        printf("read trust_file fail: %d\n", ret);
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

