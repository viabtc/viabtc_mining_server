/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/01, create
 */

# include "gw_config.h"

struct settings settings;

int read_vardiff(json_t *root)
{
    ERR_RET_LN(read_cfg_int(root, "diff_min", &settings.diff_min, true, 0));
    ERR_RET_LN(read_cfg_int(root, "diff_max", &settings.diff_max, true, 0));
    ERR_RET_LN(read_cfg_int(root, "diff_default", &settings.diff_default, true, 0));
    ERR_RET_LN(read_cfg_int(root, "target_time", &settings.target_time, true, 0));
    ERR_RET_LN(read_cfg_int(root, "retarget_time", &settings.retarget_time, true, 0));

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
    ret = load_cfg_svr(root, "svr", &settings.svr);
    if (ret < 0) {
        printf("load svr config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_http_svr(root, "http_svr", &settings.http_svr);
    if (ret < 0) {
        printf("load http svr config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_svr(root, "monitor", &settings.monitor);
    if (ret < 0) {
        printf("load monitor config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_rpc_clt(root, "job", &settings.job);
    if (ret < 0) {
        printf("load job config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_rpc_clt(root, "writer", &settings.writer);
    if (ret < 0) {
        printf("load writer config fail: %d\n", ret);
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
    ret = read_cfg_str(root, "coin", &settings.coin, NULL);
    if (ret < 0) {
        printf("read coin fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_str(root, "queue", &settings.queue, NULL);
    if (ret < 0) {
        printf("read queue fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_str(root, "coinbase_message_file", &settings.coinbase_message_file, NULL);
    if (ret < 0) {
        printf("read coinbase_message_file fail: %d\n", ret);
    }
    ret = read_cfg_int(root, "worker_id", &settings.worker_id, true, 0);
    if (ret < 0) {
        printf("load worker_id config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_int(root, "worker_num", &settings.worker_num, true, 0);
    if (ret < 0) {
        printf("load worker_num config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_vardiff(root);
    if (ret < 0) {
        printf("read vardiff config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_int(root, "client_max_idle_time", &settings.client_max_idle_time, false, 300);
    if (ret < 0) {
        printf("read client_max_idle_time fail: %d\n", ret);
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

