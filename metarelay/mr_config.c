/*
 * Description: 
 *     History: yang@haipo.me, 2016/12/03, create
 */

# include "mr_config.h"

struct settings settings;

static int read_trust(json_t *root)
{
    json_t *node = json_object_get(root, "trust");
    if (!node || !json_is_array(node)) {
        return -__LINE__;
    }
    settings.trust_count = json_array_size(node);
    settings.trust_list = malloc(settings.trust_count * sizeof(char *));
    for (size_t i = 0; i < settings.trust_count; ++i) {
        json_t *row = json_array_get(node, i);
        if (!row || !json_is_string(row)) {
            return -__LINE__;
        }
        settings.trust_list[i] = strdup(json_string_value(row));
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
    ret = load_cfg_svr(root, "svr", &settings.svr);
    if (ret < 0) {
        printf("load svr config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_svr(root, "monitor", &settings.monitor);
    if (ret < 0) {
        printf("load monitor config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = load_cfg_rpc_clt(root, "writer", &settings.writer);
    if (ret < 0) {
        printf("load writer config fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_cfg_str(root, "queue", &settings.queue, NULL);
    if (ret < 0) {
        printf("read queue fail: %d\n", ret);
        return -__LINE__;
    }
    ret = read_trust(root);
    if (ret < 0) {
        printf("load trust config fail: %d\n", ret);
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

