/*
 * Description: 
 *     History: yang@haipo.me, 2016/06/27, create
 */

# include "bp_config.h"
# include "bp_server.h"
# include "bp_peer.h"
# include "ut_pack.h"
# include "bp_request.h"

static coin_rpc *coin;
static nw_buf_pool *clt_buf_pool;
static double diff1_bignum;
static double diff_current;
static nw_timer diff_timer;
static nw_timer height_timer;
static nw_timer jobmaster_update_timer;
static nw_timer broadcast_timer;
static dict_t *peer_dict;
static dict_t *block_dict;
static int sockfd;

static int  coin_height;
static int  best_height;
static char best_hash[32];
static char last_hash[32];
static sds  best_block;
static int  notify_height;

static uint32_t protocol_version = 70015;
static char *user_agent = "/Satoshi:0.19.0.1/";
static size_t max_pkg_size = 10 * 1024 * 1024;

struct peer_info {
    nw_clt *clt;
    time_t update_time;
    bool sendheaders;
};

static int broadcast_block_with_limit(void *block, size_t block_size, int limit);
static int broadcast_header_with_limit(void *block, size_t block_size, int limit);

static double get_sha256_bignum(const char *hash)
{
    double x = (uint8_t)(hash[0]);
    for (int i = 1; i < 32; ++i) {
        x = x * 256 + (uint8_t)(hash[i]);
    }
    return x;
}

static int get_difficulty(double *diff)
{
    double start = current_timestamp();
    json_t *r = coin_rpc_cmd(coin, 1.0, "getdifficulty", NULL);
    double end = current_timestamp();
    log_trace("name: %s getdifficulty cost time: %f", coin->name, end - start);
    if (r == NULL) {
        log_error("name: %s rpc getdifficulty fail", coin->name);
        return -__LINE__;
    }
    *diff = json_number_value(r);
    json_decref(r);
    return 0;
}

static double get_block_difficulty(const char *header_hash)
{
    double hash_bignum = get_sha256_bignum(header_hash);
    return to_fixed(diff1_bignum / hash_bignum, 4);
}

static void on_diff_timer(nw_timer *timer, void *privdata)
{
    get_difficulty(&diff_current);
}

static int get_blockcount(int *height)
{
    double start = current_timestamp();
    json_t *r = coin_rpc_cmd(coin, 1.0, "getblockcount", NULL);
    double end = current_timestamp();
    log_trace("name: %s getblockcount cost time: %f", coin->name, end - start);
    if (r == NULL) {
        log_error("name: %s rpc getblockcount fail", coin->name);
        return -__LINE__;
    }
    *height = json_integer_value(r);
    json_decref(r);
    return 0;
}

static void on_height_timer(nw_timer *timer, void *privdata)
{
    get_blockcount(&coin_height);
}

static int init_coin(void)
{
    coin = coin_rpc_create(&settings.coin);
    if (coin == NULL)
        return -__LINE__;
    ERR_RET(get_difficulty(&diff_current));
    ERR_RET(get_blockcount(&coin_height));

    nw_timer_set(&diff_timer, 3600, true, on_diff_timer, NULL);
    nw_timer_start(&diff_timer);

    nw_timer_set(&height_timer, 1, true, on_height_timer, NULL);
    nw_timer_start(&height_timer);

    char *diff1_hex = "00000000FFFF0000000000000000000000000000000000000000000000000000";
    sds diff1_hash = hex2bin(diff1_hex);
    diff1_bignum = get_sha256_bignum(diff1_hash);
    sdsfree(diff1_hash);

    return 0;
}

static int decode_pkg(nw_ses *ses, void *data, size_t max)
{
    if (max < 24)
        return 0;
    if (memcmp(data, settings.start_string, 4) != 0)
        return -1;
    uint32_t payload_size = le32toh(*(uint32_t *)(data + 16));
    if (payload_size > 32 * 1000 * 1000)
        return -2;
    if (24 + payload_size > max)
        return 0;
    char payload_hash[32];
    sha256d(data + 24, payload_size, payload_hash);
    if (memcmp(data + 20, payload_hash, 4) != 0)
        return -3;
    return 24 + payload_size;
}

static int on_close(nw_ses *ses)
{
    log_error("peer: %s close", nw_sock_human_addr(&ses->peer_addr));
    return 0;
}

static int send_p2pmsg(nw_ses *ses, const char *cmd, void *msg, size_t size)
{
    static char *buf;
    static size_t buf_size;
    if (buf == NULL) {
        buf_size = max_pkg_size;
        buf = malloc(buf_size);
        if (buf == NULL)
            return -__LINE__;
    }

    char cmdbuf[12] = { 0 };
    strncpy(cmdbuf, cmd, sizeof(cmdbuf));
    char msghash[32];
    sha256d(msg, size, msghash);

    void *p = buf;
    size_t left = buf_size;
    ERR_RET_LN(pack_buf(&p, &left, settings.start_string, 4));
    ERR_RET_LN(pack_buf(&p, &left, cmdbuf, 12));
    ERR_RET_LN(pack_uint32_le(&p, &left, size));
    ERR_RET_LN(pack_buf(&p, &left, msghash, 4));
    ERR_RET_LN(pack_buf(&p, &left, msg, size));

    if (nw_ses_send(ses, buf, buf_size - left) < 0)
        return -__LINE__;
    return 0;
}

static int send_version(nw_ses *ses)
{
    char buf[1024];
    void *p = buf;
    size_t left = sizeof(buf);

    char empty_addr[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 };

    ERR_RET_LN(pack_uint32_le(&p, &left, protocol_version));
    ERR_RET_LN(pack_uint64_le(&p, &left, 1 << 3));
    ERR_RET_LN(pack_uint64_le(&p, &left, time(NULL)));
    ERR_RET_LN(pack_uint64_le(&p, &left, 0));
    ERR_RET_LN(pack_buf(&p, &left, empty_addr, sizeof(empty_addr)));
    ERR_RET_LN(pack_uint16_le(&p, &left, 0));
    ERR_RET_LN(pack_uint64_le(&p, &left, 1));
    ERR_RET_LN(pack_buf(&p, &left, empty_addr, sizeof(empty_addr)));
    ERR_RET_LN(pack_uint16_le(&p, &left, 0));
    ERR_RET_LN(pack_uint64_le(&p, &left, ((uint64_t)rand() << 32) + rand()));
    ERR_RET_LN(pack_varstr(&p, &left, user_agent, strlen(user_agent)));
    ERR_RET_LN(pack_uint32_le(&p, &left, 0));
    ERR_RET_LN(pack_char(&p, &left, 0));

    return send_p2pmsg(ses, "version", buf, sizeof(buf) - left);
}

static void on_connect(nw_ses *ses, bool result)
{
    if (result) {
        log_info("connect peer: %s success", nw_sock_human_addr(&ses->peer_addr));
        send_version(ses);
    } else {
        log_info("connect peer: %s fail", nw_sock_human_addr(&ses->peer_addr));
    }
}

static int send_verack(nw_ses *ses)
{
    return send_p2pmsg(ses, "verack", NULL, 0);
}

static int send_pong(nw_ses *ses, void *msg, size_t size)
{
    return send_p2pmsg(ses, "pong", msg, size);
}

static int send_sendheaders(nw_ses *ses)
{
    return send_p2pmsg(ses, "sendheaders", NULL, 0);
}

static int send_getdata(nw_ses *ses, uint32_t type, const char *hash)
{
    char buf[1024];
    void *p = buf;
    size_t left = sizeof(buf);

    ERR_RET_LN(pack_varint_le(&p, &left, 1));
    ERR_RET_LN(pack_uint32_le(&p, &left, type));
    ERR_RET_LN(pack_buf(&p, &left, hash, 32));

    return send_p2pmsg(ses, "getdata", buf, sizeof(buf) - left);
}

static int send_getheaders(nw_ses *ses, const char *hash)
{
    char buf[1024];
    void *p = buf;
    size_t left = sizeof(buf);
    char empty_hash[32] = { 0 };

    ERR_RET_LN(pack_uint32_le(&p, &left, protocol_version));
    ERR_RET_LN(pack_varint_le(&p, &left, 1));
    ERR_RET_LN(pack_buf(&p, &left, hash, 32));
    ERR_RET_LN(pack_buf(&p, &left, empty_hash, 32));

    return send_p2pmsg(ses, "getheaders", buf, sizeof(buf) - left);
}

static int send_inv(nw_ses *ses, uint32_t type, void *hash)
{
    char buf[1024];
    void *p = buf;
    size_t left = sizeof(buf);

    ERR_RET_LN(pack_varint_le(&p, &left, 1));
    ERR_RET_LN(pack_uint32_le(&p, &left, type));
    ERR_RET_LN(pack_buf(&p, &left, hash, 32));

    return send_p2pmsg(ses, "inv", buf, sizeof(buf) - left);
}

static int send_header(nw_ses *ses, void *header)
{
    char buf[1024];
    void *p = buf;
    size_t left = sizeof(buf);

    ERR_RET_LN(pack_varint_le(&p, &left, 1));
    ERR_RET_LN(pack_buf(&p, &left, header, 80));
    ERR_RET_LN(pack_varint_le(&p, &left, 0));

    return send_p2pmsg(ses, "headers", buf, sizeof(buf) - left);
}

static int send_block(nw_ses *ses, void *block, size_t size)
{
    return send_p2pmsg(ses, "block", block, size);
}

static int send_block_nitify(sds hash, int height, uint32_t curtime)
{
    json_t *message = json_object();
    json_object_set_new(message, "height", json_integer(height));
    json_object_set_new(message, "curtime", json_integer(curtime));
    json_object_set_new(message, "prevhash", json_string(hash));

    char *message_data = json_dumps(message, 0);
    if (message_data == NULL) {
        log_error("json_dumps fail");
        json_decref(message);
        return -__LINE__;
    }
    json_decref(message);
    log_debug("block notify msg: %s", message_data);

    rpc_pkg pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.command = CMD_HEIGHT_UPDATE;
    pkg.pkg_type = RPC_PKG_TYPE_PUSH;
    pkg.body_size = strlen(message_data);
    pkg.body = message_data;

    void *pkg_data;
    uint32_t pkg_size;
    int ret = rpc_pack(&pkg, &pkg_data, &pkg_size);
    if (ret < 0) {
        log_error("rpc_pack fail: %d", ret);
        free(message_data);
        return -__LINE__;
    }
    free(message_data);

    for (size_t i = 0; i < settings.jobmaster->count; ++i) {
        struct sockaddr_in *addr = &settings.jobmaster->arr[i];
        sendto(sockfd, pkg_data, pkg_size, 0, (struct sockaddr *)addr, sizeof(*addr));
    }

    return 0;
}

static int process_sendheaders(nw_ses *ses)
{
    struct peer_info *info = ses->privdata;
    info->sendheaders = true;
    return 0;
}

static int process_inv(nw_ses *ses, void *msg, size_t size)
{
    void *p = msg;
    size_t left = size;

    uint64_t count;
    ERR_RET_LN(unpack_varint_le(&p, &left, &count));
    if (count != 1)
        return 0;

    for (size_t i = 0; i < count; ++i) {
        uint32_t type;
        char hash[32];
        ERR_RET_LN(unpack_uint32_le(&p, &left, &type));
        ERR_RET_LN(unpack_buf(&p, &left, hash, 32));
        if (type == 2) {
            char hash_r[32];
            memcpy(hash_r, hash, 32);
            reverse_mem(hash_r, 32);
            sds hex = bin2hex(hash_r, 32);
            log_debug("peer: %s, recv inv block: %s", nw_sock_human_addr(&ses->peer_addr), hex);
            sdsfree(hex);

            sds key = sdsnewlen(hash, sizeof(hash));
            dict_entry *entry = dict_find(block_dict, key);
            if (entry == NULL) {
                if (best_height > 0)
                    send_getheaders(ses, best_hash);
                // get segwit block
                send_getdata(ses, (1 << 30) + 2, hash);
            }
            sdsfree(key);
        }
    }

    return 0;
}

static int process_headers(nw_ses *ses, void *msg, size_t size)
{
    void *p = msg;
    size_t left = size;

    uint64_t count;
    ERR_RET_LN(unpack_varint_le(&p, &left, &count));
    if (count != 1)
        return 0;

    for (size_t i = 0; i < count; ++i) {
        char header[80];
        uint64_t tx_count;
        ERR_RET_LN(unpack_buf(&p, &left, header, 80));
        ERR_RET_LN(unpack_varint_le(&p, &left, &tx_count));

        char hash[32];
        sha256d(header, sizeof(header), hash);
        char hash_r[32];
        memcpy(hash_r, hash, 32);
        reverse_mem(hash_r, 32);
        sds hex = bin2hex(hash_r, 32);
        log_info("peer: %s, recv header: %s", nw_sock_human_addr(&ses->peer_addr), hex);

        if (best_height > 0 && memcmp(header + 4, best_hash, 32) == 0) {
            double diff = get_block_difficulty(hash_r);
            if (diff < diff_current) {
                sdsfree(hex);
                return -__LINE__;
            }

            int height = best_height + 1;
            if (height > notify_height) {
                uint32_t block_time = le32toh(*(uint32_t *)(header + 68));
                uint32_t curtime = time(NULL);
                if (curtime <= block_time) {
                    curtime = block_time + 1;
                }
                int ret = send_block_nitify(hex, height, curtime);
                if (ret < 0) {
                    log_error("send_block_nitify fail: %d", ret);
                    sdsfree(hex);
                    return -__LINE__;
                }
                notify_height = height;
            }
        } else if (best_height > 0) {
            sdsfree(hex);
            continue;
        }

        sds key = sdsnewlen(hash, sizeof(hash));
        dict_entry *entry = dict_find(block_dict, key);
        if (entry == NULL) {
            // get segwit block
            send_getdata(ses, (1 << 30) + 2, hash);
        }
        sdsfree(key);
        sdsfree(hex);
    }

    return 0;
}

static int get_height_from_coinbase(void *p, size_t left)
{
    uint32_t tx_version;
    ERR_RET_LN(unpack_uint32_le(&p, &left, &tx_version));
    bool is_segwit_tx = false;
    if (*(uint8_t *)p == 0) {
        is_segwit_tx = true;
        uint8_t marker, flag;
        ERR_RET_LN(unpack_char(&p, &left, &marker));
        ERR_RET_LN(unpack_char(&p, &left, &flag));
    }

    void *coinbase = NULL;
    size_t coinbase_size = 0;

    uint64_t tx_in_count;
    ERR_RET_LN(unpack_varint_le(&p, &left, &tx_in_count));
    for (size_t i = 0; i < tx_in_count; ++i) {
        if (left < 36)
            return -__LINE__;
        left -= 36;
        p += 36;
        uint64_t script_size;
        ERR_RET_LN(unpack_varint_le(&p, &left, &script_size));
        if (left < script_size)
            return -__LINE__;
        if (script_size && i == 0) {
            coinbase = p;
            coinbase_size = script_size;
        }
        left -= script_size;
        p += script_size;
        uint32_t sequence;
        ERR_RET_LN(unpack_uint32_le(&p, &left, &sequence));
    }

    uint64_t tx_out_count;
    ERR_RET_LN(unpack_varint_le(&p, &left, &tx_out_count));
    for (size_t i = 0; i < tx_out_count; ++i) {
        uint64_t value;
        ERR_RET_LN(unpack_uint64_le(&p, &left, &value));
        uint64_t script_size;
        ERR_RET_LN(unpack_varint_le(&p, &left, &script_size));
        if (left < script_size)
            return -__LINE__;
        left -= script_size;
        p += script_size;
    }

    if (is_segwit_tx) {
        for (size_t i = 0; i < tx_in_count; ++i) {
            uint64_t witness_count;
            ERR_RET_LN(unpack_varint_le(&p, &left, &witness_count));
            for (size_t j = 0; j < witness_count; ++j) {
                uint64_t witness_size;
                ERR_RET_LN(unpack_varint_le(&p, &left, &witness_size));
                if (left < witness_size)
                    return -__LINE__;
                if (coinbase == NULL && i == 0) {
                    coinbase = p;
                    coinbase_size = witness_size;
                }
                left -= witness_size;
                p += witness_size;
            }
        }
    }

    if (!coinbase) {
        return -__LINE__;
    }

    int64_t height = 0;
    ERR_RET_LN(unpack_oppushint_le(&coinbase, &coinbase_size, &height));
    return height;
}

static int process_block(nw_ses *ses, void *msg, size_t size)
{
    if (size < 80) {
        log_error("invalid block size: %zu", size);
        return -__LINE__;
    }

    char hash[32];
    sha256d(msg, 80, hash);
    sds key = sdsnewlen(hash, sizeof(hash));
    if (dict_add(block_dict, key, NULL) < 0) {
        sdsfree(key);
    }

    char hash_r[32];
    memcpy(hash_r, hash, 32);
    reverse_mem(hash_r, sizeof(hash_r));
    sds hex = bin2hex(hash_r, 32);
    if (ses) {
        log_debug("peer: %s, recv block: %s, size: %zu", nw_sock_human_addr(&ses->peer_addr), hex, size);
    }

    double diff = get_block_difficulty(hash_r);
    if (diff < diff_current) {
        sdsfree(hex);
        return 0;
    }

    void *p = msg + 80;
    size_t left = size - 80;
    uint64_t tx_count;
    if (unpack_varint_le(&p, &left, &tx_count) < 0) {
        sdsfree(hex);
        return -__LINE__;
    }
    int height = get_height_from_coinbase(p, left);
    if (height < 0) {
        sdsfree(hex);
        return -__LINE__;
    }

    best_height = height;
    memcpy(last_hash, best_hash, sizeof(best_hash));
    memcpy(best_hash, hash, sizeof(hash));
    sdsclear(best_block);
    best_block = sdscatlen(best_block, msg, size);
    log_info("update best block: %s, height: %d, size: %zu", hex, best_height, size);

    if (best_height > notify_height) {
        uint32_t block_time = le32toh(*(uint32_t *)(msg + 68));
        uint32_t curtime = time(NULL);
        if (curtime <= block_time) {
            curtime = block_time + 1;
        }
        int ret = send_block_nitify(hex, best_height, curtime);
        if (ret < 0) {
            log_error("send_block_nitify fail: %d", ret);
            sdsfree(hex);
            return -__LINE__;
        }
        notify_height = best_height;
    }
    if (ses) {
        broadcast_block_update(msg, size);
    }
    sdsfree(hex);

    return 0;
}

static int process_getheaders(nw_ses *ses, void *msg, size_t size)
{
    void *p = msg;
    size_t left = size;
    uint32_t version;
    uint64_t count;
    ERR_RET_LN(unpack_uint32_le(&p, &left, &version));
    ERR_RET_LN(unpack_varint_le(&p, &left, &count));
    if (count > 0) {
        char hash[32];
        ERR_RET_LN(unpack_buf(&p, &left, hash, 32));
        if (memcmp(hash, last_hash, sizeof(hash)) == 0) {
            send_header(ses, best_block);
        }
    }
    return 0;
}

static int process_getdata(nw_ses *ses, void *msg, size_t size)
{
    void *p = msg;
    size_t left = size;
    uint64_t count;
    ERR_RET_LN(unpack_varint_le(&p, &left, &count));
    for (size_t i = 0; i < count; ++i) {
        uint32_t type;
        char hash[32];
        ERR_RET_LN(unpack_uint32_le(&p, &left, &type));
        ERR_RET_LN(unpack_buf(&p, &left, hash, 32));
        if (type == 2 && memcmp(hash, best_hash, 32) == 0) {
            send_block(ses, best_block, sdslen(best_block));
        }
    }
    return 0;
}

static void on_recv_pkg(nw_ses *ses, void *data, size_t size)
{
    char cmd[13] = { 0 };
    memcpy(cmd, data + 4, 12);
    void *payload = data + 24;
    uint32_t payload_size = le32toh(*(uint32_t *)(data + 16));
    log_debug("peer: %s, cmd: %s, size: %u", nw_sock_human_addr(&ses->peer_addr), cmd, payload_size);

    if (strcmp(cmd, "version") == 0) {
        int ret = send_verack(ses);
        if (ret < 0) {
            log_error("send_verack fail: %d", ret);
        }
    } else if (strcmp(cmd, "verack") == 0) {
        int ret = send_sendheaders(ses);
        if (ret < 0) {
            log_error("send_sendheaders fail: %d", ret);
        }
    } else if (strcmp(cmd, "ping") == 0) {
        int ret = send_pong(ses, payload, payload_size);
        if (ret < 0) {
            log_error("send_pong fail: %d", ret);
        }
    } else if (strcmp(cmd, "sendheaders") == 0) {
        int ret = process_sendheaders(ses);
        if (ret < 0) {
            log_error("process_sendheaders fail: %d", ret);
        }
    } else if (strcmp(cmd, "inv") == 0) {
        int ret = process_inv(ses, payload, payload_size);
        if (ret < 0) {
            log_error("process_inv fail: %d", ret);
        }
    } else if (strcmp(cmd, "headers") == 0) {
        int ret = process_headers(ses, payload, payload_size);
        if (ret < 0) {
            log_error("process_headers fail: %d", ret);
        }
    } else if (strcmp(cmd, "block") == 0) {
        int ret = process_block(ses, payload, payload_size);
        if (ret < 0) {
            log_error("process_block fail: %d", ret);
        }
    } else if (strcmp(cmd, "getheaders") == 0) {
        int ret = process_getheaders(ses, payload, payload_size);
        if (ret < 0) {
            log_error("process_getheaders fail: %d", ret);
        }
    } else if (strcmp(cmd, "getdata") == 0) {
        int ret = process_getdata(ses, payload, payload_size);
        if (ret < 0) {
            log_error("process_getdata fail: %d", ret);
        }
    }
}

static void on_error_msg(nw_ses *ses, const char *msg)
{
    log_error("peer: %s error msg: %s", nw_sock_human_addr(&ses->peer_addr), msg);
}

int update_peer(void)
{
    time_t now = time(NULL);
    json_error_t error;
    json_t *root = json_load_file(settings.peer_config_path, 0, &error);
    if (root == NULL) {
        log_error("json_load_file from: %s fail: %s in line: %d", settings.peer_config_path, error.text, error.line);
        return -__LINE__;
    }
    json_t *peers = json_object_get(root, "peers");
    if (!peers || !json_is_array(peers)) {
        json_decref(root);
        return -__LINE__;
    }

    for (int i = 0; i < json_array_size(peers); ++i) {
        json_t *row = json_array_get(peers, i);
        if (!json_is_string(row)) {
            json_decref(root);
            return -__LINE__;
        }

        sds key = sdsnew(json_string_value(row));
        dict_entry *entry = dict_find(peer_dict, key);
        if (entry) {
            struct peer_info *info = entry->val;
            info->update_time = now;
            log_debug("peer: %s exist", key);
            sdsfree(key);
            continue;
        }
        sdsfree(key);

        log_debug("add peer: %s", json_string_value(row));
        nw_clt_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        sds sock_cfg = sdsempty();
        sock_cfg = sdscatprintf(sock_cfg, "tcp@%s", json_string_value(row));
        if (nw_sock_cfg_parse(sock_cfg, &cfg.addr, &cfg.sock_type) < 0) {
            log_error("add peer: %s fail", json_string_value(row));
            sdsfree(sock_cfg);
            json_decref(root);
            return -__LINE__;
        }
        sdsfree(sock_cfg);
        cfg.buf_pool = clt_buf_pool;
        cfg.max_pkg_size = max_pkg_size;
        cfg.reconnect_timeout = settings.reconnect_timeout;

        nw_clt_type type;
        memset(&type, 0, sizeof(type));
        type.decode_pkg = decode_pkg;
        type.on_close = on_close;
        type.on_connect = on_connect;
        type.on_recv_pkg = on_recv_pkg;
        type.on_error_msg = on_error_msg;

        struct peer_info *info = malloc(sizeof(struct peer_info));
        memset(info, 0, sizeof(struct peer_info));
        info->update_time = now;
        info->clt = nw_clt_create(&cfg, &type, info);
        if (info->clt == NULL) {
            log_error("add peer: %s fail", json_string_value(row));
            free(info);
            json_decref(root);
            return -__LINE__;
        }
        if (nw_clt_start(info->clt) < 0) {
            log_error("add peer: %s fail", json_string_value(row));
            free(info);
            json_decref(root);
            return -__LINE__;
        }
        if (dict_add(peer_dict, sdsnew(json_string_value(row)), info) < 0) {
            log_error("add peer: %s fail", json_string_value(row));
            free(info);
            json_decref(root);
            return -__LINE__;
        }
    }

    json_decref(root);

    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(peer_dict);
    while ((entry = dict_next(iter)) != NULL) {
        struct peer_info *info = entry->val;
        if (info->update_time != now) {
            log_debug("remove peer: %s", (sds)entry->key);
            dict_delete(peer_dict, entry->key);
        }
    }
    dict_release_iterator(iter);

    return 0;
}

static uint32_t peer_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sdslen((sds)key));
}
static int peer_dict_key_compare(const void *key1, const void *key2)
{
    return sdscmp((sds)key1, (sds)key2);
}
static void peer_dict_key_free(void *key)
{
    sdsfree((sds)key);
}
static void peer_dict_val_free(void *val)
{
    struct peer_info *info = val;
    if (info->clt) {
        nw_clt_close(info->clt);
        nw_clt_release(info->clt);
    }
    free(info);
}

static uint32_t block_dict_hash_func(const void *key)
{
    return dict_generic_hash_function(key, sdslen((sds)key));
}
static int block_dict_key_compare(const void *key1, const void *key2)
{
    return sdscmp((sds)key1, (sds)key2);
}
static void block_dict_key_free(void *key)
{
    sdsfree((sds)key);
}

static void inetv4_list_free(inetv4_list *list)
{
    if (list) {
        if (list->arr)
            free(list->arr);
        free(list);
    }
}

static int on_jobmaster_callback(json_t *reply)
{
    if (!reply) {
        log_fatal("get jobmaster config null");
        return -__LINE__;
    }

    char *str_new = json_dumps(reply, 0);
    char *str_old = json_dumps(settings.jobmaster_cfg, 0);
    log_info("new jobmaster config: %s, old jobmaster config: %s", str_new, str_old);

    inetv4_list *jobmaster = malloc(sizeof(inetv4_list));
    int ret = load_cfg_inetv4_list_direct(reply, jobmaster);
    if (ret < 0) {
        log_fatal("update jobmaster fail, ret: %d, json reply: %s", ret, str_new);
        free(str_new);
        free(str_old);
        inetv4_list_free(jobmaster);
        return -__LINE__;
    }
    free(str_new);
    free(str_old);

    json_decref(settings.jobmaster_cfg);
    settings.jobmaster_cfg = reply;

    inetv4_list_free(settings.jobmaster);
    settings.jobmaster = jobmaster;
    log_info("update jobmaster config success");

    return 0;
}

static void on_jobmaster_update(nw_timer *timer, void *privdata)
{
    update_jobmaster_config(on_jobmaster_callback);
}

int init_peer(void)
{
    dict_types peer_type;
    memset(&peer_type, 0, sizeof(peer_type));
    peer_type.hash_function = peer_dict_hash_func;
    peer_type.key_compare = peer_dict_key_compare;
    peer_type.key_destructor = peer_dict_key_free;
    peer_type.val_destructor = peer_dict_val_free;

    peer_dict = dict_create(&peer_type, 64);
    if (peer_dict == NULL) {
        return -__LINE__;
    }

    dict_types block_type;
    memset(&block_type, 0, sizeof(block_type));
    block_type.hash_function = block_dict_hash_func;
    block_type.key_compare = block_dict_key_compare;
    block_type.key_destructor = block_dict_key_free;

    block_dict = dict_create(&block_type, 64);
    if (block_dict == NULL) {
        return -__LINE__;
    }

    ERR_RET(init_coin());

    clt_buf_pool = nw_buf_pool_create(max_pkg_size);
    if (clt_buf_pool == NULL)
        return -__LINE__;
    ERR_RET(update_peer());

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -__LINE__;
    best_block = sdsempty();

    nw_timer_set(&jobmaster_update_timer, settings.jobmaster_update_interval, true, on_jobmaster_update, NULL);
    nw_timer_start(&jobmaster_update_timer);

    return 0;
}

static int broadcast_block_with_limit(void *block, size_t block_size, int limit)
{
    char hash[32];
    sha256d(block, 80, hash);
    char hash_r[32];
    memcpy(hash_r, hash, sizeof(hash));
    reverse_mem(hash_r, sizeof(hash_r));
    sds hex = bin2hex(hash_r, sizeof(hash_r));
    log_info("broadcast block: %s, size: %zu", hex, block_size);
    sdsfree(hex);

    int count = 0;
    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(peer_dict);
    while ((entry = dict_next(iter)) != NULL) {
        struct peer_info *info = entry->val;
        if (nw_clt_connected(info->clt)) {
            log_info("send block to: %s", nw_sock_human_addr(&info->clt->ses.peer_addr));
            send_p2pmsg(&info->clt->ses, "block", block, block_size);
            if (limit) {
                count += 1;
                if (count >= limit) {
                    break;
                }
            }
        }
    }
    dict_release_iterator(iter);
    process_block(NULL, block, block_size);

    return 0;
}

static void on_broadcast_timeout(nw_timer *timer, void *privdata)
{
    sds block = privdata;
    int ret = broadcast_header_with_limit(block, sdslen(block), 0);
    if (ret < 0) {
        log_error("broadcast_header_with_limit fail: %d", ret);
    }
    sdsfree(block);
}

int broadcast_block(void *block, size_t block_size)
{
    static char last_block_hash[32];
    char hash[32];
    sha256d(block, 80, hash);
    if (memcmp(hash, last_block_hash, sizeof(hash)) == 0) {
        return 0;
    }
    memcpy(last_block_hash, hash, sizeof(hash));

    ERR_RET(broadcast_block_with_limit(block, block_size, settings.broadcast_limit));
    if (!nw_timer_active(&broadcast_timer) && peer_dict->used > (uint32_t)settings.broadcast_limit) {
        nw_timer_set(&broadcast_timer, 1, false, on_broadcast_timeout, sdsnewlen(block, block_size));
        nw_timer_start(&broadcast_timer);
    }

    return 0;
}

static int broadcast_header_with_limit(void *block, size_t block_size, int limit)
{
    char hash[32];
    sha256d(block, 80, hash);
    char hash_r[32];
    memcpy(hash_r, hash, sizeof(hash));
    reverse_mem(hash_r, sizeof(hash_r));
    sds hex = bin2hex(hash_r, sizeof(hash_r));
    log_info("broadcast header: %s", hex);
    sdsfree(hex);

    int count = 0;
    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(peer_dict);
    while ((entry = dict_next(iter)) != NULL) {
        struct peer_info *info = entry->val;
        if (nw_clt_connected(info->clt)) {
            if (info->sendheaders) {
                log_info("send header to: %s", nw_sock_human_addr(&info->clt->ses.peer_addr));
                send_header(&info->clt->ses, block);
            } else {
                log_info("send inv to: %s", nw_sock_human_addr(&info->clt->ses.peer_addr));
                send_inv(&info->clt->ses, 2, hash);
            }
            if (limit) {
                count += 1;
                if (count >= limit) {
                    break;
                }
            }
        }
    }
    dict_release_iterator(iter);
    process_block(NULL, block, block_size);

    return 0;
}

int broadcast_header(void *block, size_t block_size)
{
    static char last_block_hash[32];
    char hash[32];
    sha256d(block, 80, hash);
    if (memcmp(hash, last_block_hash, sizeof(hash)) == 0) {
        return 0;
    }
    memcpy(last_block_hash, hash, sizeof(hash));

    return broadcast_header_with_limit(block, block_size, settings.broadcast_limit);
}

sds get_peer_status(void)
{
    sds reply = sdsempty();
    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(peer_dict);
    while ((entry = dict_next(iter)) != NULL) {
        struct peer_info *info = entry->val;
        reply = sdscatprintf(reply, "%s %d\n", nw_sock_human_addr(&info->clt->ses.peer_addr), nw_clt_connected(info->clt));
    }
    dict_release_iterator(iter);
    return reply;
}

int get_peer_limit(void)
{
    return dict_size(peer_dict);
}

int get_peer_num(void)
{
    int num = 0;
    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(peer_dict);
    while ((entry = dict_next(iter)) != NULL) {
        struct peer_info *info = entry->val;
        if (nw_clt_connected(info->clt)) {
            num++;
        }
    }
    dict_release_iterator(iter);

    return num;
}

