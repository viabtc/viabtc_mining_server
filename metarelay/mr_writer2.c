/*
 * Description: 
 *     History: yang@haipo.me, 2016/12/07, create
 */

# include "mr_config.h"
# include "mr_writer2.h"
# include "ut_queue.h"
# include "nw_timer.h"

# define QUEUE_SHM_KEY      0x18040701
# define MAX_STATE_COUNT    1000

static rpc_clt *clt;
static queue_t queue;
static nw_timer timer;
static nw_state *state;

static void clt_on_connect(nw_ses *ses, bool result)
{
    if (result) {
        log_info("connect writer: %s success", nw_sock_human_addr(&ses->peer_addr));
    } else {
        log_info("connect writer: %s fail", nw_sock_human_addr(&ses->peer_addr));
    }
}

static void clt_on_recv_pkg(nw_ses *ses, rpc_pkg *pkg)
{
    log_debug("reply sequence: %u from: %s", pkg->sequence, nw_sock_human_addr(&ses->peer_addr));
    nw_state_del(state, pkg->sequence);
}

static int send_pkg(rpc_pkg *pkg)
{
    nw_state_entry *entry = nw_state_add(state, 10.0, 0);
    if (entry == NULL)
        return -__LINE__;
    rpc_pkg *state_data = entry->data;
    memcpy(state_data, pkg, sizeof(rpc_pkg));
    state_data->body = malloc(state_data->body_size);
    memcpy(state_data->body, pkg->body, state_data->body_size);
    state_data->sequence = entry->id;

    rpc_clt_send(clt, state_data);
    log_debug("send pkg, command: %u sequence: %u", state_data->command, state_data->sequence);

    return 0;
}

static int init_clt(void)
{
    rpc_clt_type type;
    memset(&type, 0, sizeof(type));
    type.on_connect = clt_on_connect;
    type.on_recv_pkg = clt_on_recv_pkg;

    clt = rpc_clt_create(&settings.writer2, &type);
    if (clt == NULL)
        return -__LINE__;
    if (rpc_clt_start(clt) < 0)
        return -__LINE__;

    return 0;
}

static int init_queue(void)
{
    int ret = queue_init(&queue, "writer", QUEUE_SHM_KEY, 10 * 1024 * 1024, settings.queue2, 1024 * 1024 * 1024);
    if (ret < 0) {
        log_error("queue_init fail: %d", ret);
        return -__LINE__;
    }

    return 0;
}

static void state_on_timeout(nw_state_entry *entry)
{
    log_error("state entry: %u timeout, retry", entry->id);
    send_pkg((rpc_pkg *)entry->data);
}

static void state_on_release(nw_state_entry *entry)
{
    free(((rpc_pkg *)entry->data)->body);
}

static int init_state(void)
{
    nw_state_type type;
    type.on_timeout = state_on_timeout;
    type.on_release = state_on_release;

    state = nw_state_create(&type, sizeof(struct rpc_pkg));
    if (state == NULL)
        return -__LINE__;

    return 0;
}

static void on_timer(nw_timer *timer, void *privdata)
{
    while (state->used < MAX_STATE_COUNT && queue_num(&queue) > 0) {
        void *data;
        uint32_t size;
        int ret = queue_pop(&queue, &data, &size);
        if (ret < 0) {
            log_error("queue_pop fail: %d", ret);
            return;
        }

        ret = rpc_decode(NULL, data, size);
        if (ret < 0) {
            log_error("rpc_decode fail: %d", ret);
            return;
        } else if ((uint32_t)ret != size) {
            log_error("invalid rpc size: %u", size);
            return;
        }

        struct rpc_pkg pkg;
        memcpy(&pkg, data, RPC_PKG_HEAD_SIZE);
        pkg.ext = data + RPC_PKG_HEAD_SIZE;
        pkg.body = pkg.ext + pkg.ext_size;

        ret = send_pkg(&pkg);
        if (ret < 0) {
            log_error("send_pkg fail: %d", ret);
            return;
        }
    }
}

int init_writer2(void)
{
    ERR_RET(init_clt());
    ERR_RET(init_queue());
    ERR_RET(init_state());

    nw_timer_set(&timer, 1, true, on_timer, NULL);
    nw_timer_start(&timer);

    return 0;
}

int push_message2(rpc_pkg *pkg)
{
    if (state->used < MAX_STATE_COUNT) {
        return send_pkg(pkg);
    }

    void *data;
    uint32_t size;
    rpc_pack(pkg, &data, &size);
    int ret = queue_push(&queue, data, size);
    if (ret < 0) {
        log_error("queue_push fail: %d", ret);
        return -__LINE__;
    }

    return 0;
}

