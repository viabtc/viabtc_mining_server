/*
 * Description: gateway server
 *     History: yang@haipo.me, 2016/04/01, create
 */

# include "ut_title.h"
# include "ut_signal.h"
# include "gw_job.h"
# include "gw_cli.h"
# include "gw_config.h"
# include "gw_worker.h"
# include "gw_listener.h"
# include "gw_writer.h"
# include "gw_aggregator.h"
# include "gw_http.h"

const char *version = "0.1.0";
nw_timer cron_timer;
static bool is_aggregator = false;

static void on_cron_check(nw_timer *timer, void *data)
{
    dlog_check_all();
    if (signal_exit) {
        nw_loop_break();
        if (is_aggregator) {
            aggregator_flush();
        }
        signal_exit = 0;
    }
}

static int init_process(void)
{
    if (settings.process.file_limit) {
        if (set_file_limit(settings.process.file_limit) < 0) {
            return -__LINE__;
        }
    }
    if (settings.process.core_limit) {
        if (set_core_limit(settings.process.core_limit) < 0) {
            return -__LINE__;
        }
    }

    return 0;
}

static int init_log(void)
{
    default_dlog = dlog_init(settings.log.path, DLOG_SHIFT_BY_SIZE | DLOG_LOG_PID, 100*1024*1024, 100, 0);
    if (default_dlog == NULL)
        return -__LINE__;
    default_dlog_flag = dlog_read_flag(settings.log.flag);
    if (alert_init(&settings.alert) < 0)
        return -__LINE__;
    dlog_on_fatal = alert_msg;

    return 0;
}

int main(int argc, char *argv[])
{
    printf("process: %s version: %s, compile date: %s %s\n", "geteway", version, __DATE__, __TIME__);

    if (argc != 2) {
        printf("usage: %s config.json\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    if (process_exist("gateway.exe") != 0) {
        printf("process exist\n");
        exit(EXIT_FAILURE);
    }
    process_title_init(argc, argv);

    int ret;
    ret = load_config(argv[1]);
    if (ret < 0) {
        error(EXIT_FAILURE, errno, "load config fail: %d", ret);
    }
    ret = init_process();
    if (ret < 0) {
        error(EXIT_FAILURE, errno, "init process fail: %d", ret);
    }
    ret = init_log();
    if (ret < 0) {
        error(EXIT_FAILURE, errno, "init log fail: %d", ret);
    }

    int pid;
    pid = fork();
    if (pid < 0) {
        error(EXIT_FAILURE, errno, "fork error");
    } else if (pid == 0) {
        process_title_set("gateway_listener");
        daemon(1, 1);
        process_keepalive();

        ret = init_listener();
        if (ret < 0) {
            error(EXIT_FAILURE, errno, "init listener fail: %d", ret);
        }
        dlog_set_no_shift(default_dlog);

        goto run;
    }

    for (int i = 0; i < settings.worker_num; ++i) {
        pid = fork();
        if (pid < 0) {
            error(EXIT_FAILURE, errno, "fork error");
        } else if (pid == 0) {
            process_title_set("gateway_worker_%d", i);
            daemon(1, 1);
            process_keepalive();

            ret = init_worker(i);
            if (ret < 0) {
                error(EXIT_FAILURE, errno, "init worker fail: %d", ret);
            }
            ret = init_job();
            if (ret < 0) {
                error(EXIT_FAILURE, errno, "init job fail: %d", ret);
            }
            ret = init_http_server(i);
            if (ret < 0) {
                error(EXIT_FAILURE, errno, "init http server fail: %d", ret);
            }
            ret = init_cli(i);
            if (ret < 0) {
                error(EXIT_FAILURE, errno, "init cli fail: %d", ret);
            }
            if (i != 0) {
                dlog_set_no_shift(default_dlog);
            }

            goto run;
        }
    }

    process_title_set("gateway_aggregator");
    daemon(1, 1);
    process_keepalive();

    is_aggregator = true;
    ret = init_writer();
    if (ret < 0) {
        error(EXIT_FAILURE, errno, "init writer fail: %d", ret);
    }
    ret = init_aggregator();
    if (ret < 0) {
        error(EXIT_FAILURE, errno, "init aggregator fail: %d", ret);
    }
    ret = init_cli(settings.worker_num);
    if (ret < 0) {
        error(EXIT_FAILURE, errno, "init cli fail: %d", ret);
    }
    dlog_set_no_shift(default_dlog);

run:
    nw_timer_set(&cron_timer, 0.5, true, on_cron_check, NULL);
    nw_timer_start(&cron_timer);

    log_vip("server start");
    dlog_stderr("server start");
    nw_loop_run();
    log_vip("server stop");

    return 0;
}

