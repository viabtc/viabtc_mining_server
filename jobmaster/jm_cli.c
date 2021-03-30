/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/04, create
 */

# include "jm_cli.h"
# include "jm_job.h"
# include "jm_aux.h"
# include "jm_config.h"
# include "jm_server.h"

static cli_svr *svr;

static sds on_cmd_main_blocknotify(const char *cmd, int argc, sds *argv)
{
    on_main_blocknotify();
    log_info("cmd: %s", cmd);
    return sdsnew("ok\n");
}

static sds on_cmd_aux_blocknotify(const char *cmd, int argc, sds *argv)
{
    if (argc != 1) {
        sds reply = sdsempty();
        return sdscatprintf(reply, "usage: %s aux_name\n", cmd);
    }
    sds aux_name = argv[0];
    on_aux_blocknotify(aux_name);
    log_info("cmd: %s", cmd);
    return sdsnew("ok\n");
}

static sds on_cmd_add_ban(const char *cmd, int argc, sds *argv)
{
    if (argc < 2) {
        sds reply = sdsempty();
        return sdscatprintf(reply, "usage: %s limit ip...\n", cmd);
    }

    int limit = atoi(argv[0]);
    json_t *ip_list = json_array();
    for (int i = 1; i < argc; ++i) {
        json_array_append_new(ip_list, json_string(argv[i]));
    }
    broadcast_add_ban_ip(ip_list, limit);
    json_decref(ip_list);

    return sdsnew("ok\n");
}

static sds on_cmd_del_ban(const char *cmd, int argc, sds *argv)
{
    if (argc < 1) {
        sds reply = sdsempty();
        return sdscatprintf(reply, "usage: %s ip...\n", cmd);
    }

    json_t *ip_list = json_array();
    for (int i = 0; i < argc; ++i) {
        json_array_append_new(ip_list, json_string(argv[i]));
    }
    broadcast_del_ban_ip(ip_list);
    json_decref(ip_list);

    return sdsnew("ok\n");
}

static sds on_cmd_listban(const char *cmd, int argc, sds *argv)
{
    return get_ban_ip_list();
}

static sds on_set_coinbase(const char *cmd, int argc, sds *argv)
{
    if (argc != 1) {
        sds reply = sdsempty();
        return sdscatprintf(reply, "usage: %s \"msg\"\n", cmd);
    }
    set_coinbase_message(argv[0]);
    return sdsnew("ok\n");
}

static sds on_get_coinbase(const char *cmd, int argc, sds *argv)
{
    sds reply = sdsempty();
    return sdscatprintf(reply, "%s\n", get_coinbase_message());
}

static sds on_clear_coinbase(const char *cmd, int argc, sds *argv)
{
    clear_coinbase_message();
    return sdsnew("ok\n");
}

static sds on_cmd_alert(const char *cmd, int argc, sds *argv)
{
    if (argc != 1) {
        sds reply = sdsempty();
        return sdscatprintf(reply, "usage: %s \"msg\"\n", cmd);
    }
    log_fatal("%s", argv[0]);
    return sdsnew("ok\n");
}

int init_cli(void)
{
    svr = cli_svr_create(&settings.cli);
    if (svr == NULL) {
        return -__LINE__;
    }

    cli_svr_add_cmd(svr, "addban", on_cmd_add_ban);
    cli_svr_add_cmd(svr, "delban", on_cmd_del_ban);
    cli_svr_add_cmd(svr, "listban", on_cmd_listban);
    cli_svr_add_cmd(svr, "blocknotify", on_cmd_main_blocknotify);
    cli_svr_add_cmd(svr, "aux_blocknotify", on_cmd_aux_blocknotify);
    cli_svr_add_cmd(svr, "setcoinbase", on_set_coinbase);
    cli_svr_add_cmd(svr, "getcoinbase", on_get_coinbase);
    cli_svr_add_cmd(svr, "clearcoinbase", on_clear_coinbase);
    cli_svr_add_cmd(svr, "alert", on_cmd_alert);

    return 0;
}

