/*
 * Description: 
 *     History: yang@haipo.me, 2016/03/31, create
 */

# ifndef _UT_COIN_H_
# define _UT_COIN_H_

# include <stdint.h>
# include <jansson.h>
# include <curl/curl.h>
# include "ut_sds.h"

typedef struct coin_daemon {
    char *host;
    int   port;
    char *user;
    char *pass;
} coin_daemon;

typedef struct coin_daemon_node {
    struct coin_daemon daemon;
    struct coin_daemon_node *prev;
    struct coin_daemon_node *next;
} coin_daemon_node;

typedef struct coin_rpc_cfg {
    char *name;
    uint32_t count;
    coin_daemon *arr;
} coin_rpc_cfg;

typedef struct coin_rpc {
    char *name;
    uint32_t count;
    coin_daemon_node *list;
} coin_rpc;

coin_rpc *coin_rpc_create(coin_rpc_cfg *cfg);
void coin_rpc_release(coin_rpc *rpc);
json_t *coin_rpc_cmd(coin_rpc *rpc, double timeout, const char *method, json_t *params);

json_t *coin_get_json(coin_rpc *rpc, double timeout, const char *path, long *http_code);
json_t *coin_post(coin_rpc *rpc, double timeout, const char *path, const char *data, long *http_code);

# endif

