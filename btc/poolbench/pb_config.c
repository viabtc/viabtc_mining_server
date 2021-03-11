/*
 * Description: 
 *     History: yang@haipo.me, 2016/06/22, create
 */

# include "pb_config.h"
# include "pb_request.h"

struct settings settings;

static int load_cfg_jobmaster(json_t *root, const char *key)
{
    int ret = read_cfg_str(root, key, &settings.jobmaster_url, NULL);
    if (ret < 0) {
        return -__LINE__;
    }

    ret = init_jobmaster_config();
    if (ret < 0) {
        return -__LINE__;
    }

    settings.jobmaster = malloc(sizeof(inetv4_list));
    ret = load_cfg_inetv4_list_direct(settings.jobmaster_cfg, settings.jobmaster);
    if (ret < 0) {
        char *str = json_dumps(settings.jobmaster_cfg, 0);
        log_error("load cfg jobmaster fail, jobmaster_cfg: %s", str);
        free(str);
        return -__LINE__;
    }

    return 0;
}

int read_pool_list(json_t *root, const char *key)
{
    json_t *node = json_object_get(root, key);
    if (!node || !json_is_array(node)) {
        return -__LINE__;
    }
    settings.pool_count = json_array_size(node);
    settings.pool_list = malloc(sizeof(struct pool_cfg) * settings.pool_count);
    for (int i = 0; i < settings.pool_count; ++i) {
        json_t *row = json_array_get(node, i);
        if (!json_is_object(row))
            return -__LINE__;
        ERR_RET_LN(read_cfg_str(row, "name", &settings.pool_list[i].name, NULL));
        ERR_RET_LN(read_cfg_str(row, "host", &settings.pool_list[i].host, NULL));
        ERR_RET_LN(read_cfg_int(row, "port", &settings.pool_list[i].port, true, 0));
        ERR_RET_LN(read_cfg_str(row, "user", &settings.pool_list[i].user, NULL));
        ERR_RET_LN(read_cfg_str(row, "pass", &settings.pool_list[i].pass, NULL));
        ERR_RET_LN(read_cfg_bool(row, "is_notify", &settings.pool_list[i].is_notify, false, true));
        ERR_RET_LN(read_cfg_bool(row, "is_self", &settings.pool_list[i].is_self, false, false));
    }

    return 0;
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
    ret = load_cfg_alert(root, "alert", &settings.alert);
    if (ret < 0) {
        printf("load alert config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_str(root, "request_auth", &settings.request_auth, NULL);
    if (ret < 0) {
        printf("read request_auth fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_cli_svr(root, "cli", &settings.cli);
    if (ret < 0) {
        printf("load cli config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_jobmaster(root, "jobmaster_url");
    if (ret < 0) {
        printf("load cfg jobmaster fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_int(root, "jobmaster_update_interval", &settings.jobmaster_update_interval, false, 30);
    if (ret < 0) {
        printf("read jobmaster_update_interval config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_pool_list(root, "pool_list");
    if (ret < 0) {
        printf("load pool_list config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_bool(root, "is_notify", &settings.is_notify, true, false);
    if (ret < 0) {
        printf("load is_notify config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_real(root, "max_delay", &settings.max_delay, true, 2.0);
    if (ret < 0) {
        printf("load max_delay config fail: %d\n", ret);
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

