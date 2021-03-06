/*
 * Description: 
 *     History: yang@haipo.me, 2016/03/27, create
 */

# ifndef _UT_REDIS_H_
# define _UT_REDIS_H_

# include <stddef.h>
# include <stdint.h>
# include <hiredis/hiredis.h>

typedef struct redis_cfg {
    char *host;
    int   port;
    char *auth;
} redis_cfg;

typedef struct redis_addr {
    char *host;
    int   port;
} redis_addr;

typedef struct redis_sentinel_cfg {
    char *name;
    uint32_t addr_count;
    redis_addr *addr_arr;
    int db;
} redis_sentinel_cfg;

typedef struct redis_sentinel_node {
    struct redis_addr  addr;
    struct redis_sentinel_node *prev;
    struct redis_sentinel_node *next;
} redis_sentinel_node;

typedef struct redis_sentinel {
    char *name;
    redis_sentinel_node *list;
    int db;
} redis_sentinel;

redisContext *redis_connect(redis_cfg *cfg);

redis_sentinel *redis_sentinel_create(redis_sentinel_cfg *cfg);
void redis_sentinel_release(redis_sentinel *context);

/* host should be freed by caller */
int redis_sentinel_get_master_addr(redis_sentinel *context, redis_addr *addr);
int redis_sentinel_get_slave_addr(redis_sentinel *context, redis_addr *addr);

redisContext *redis_sentinel_connect_master(redis_sentinel *context);
redisContext *redis_sentinel_connect_slave(redis_sentinel *context);

int redis_addr_cfg_parse(const char *cfg, redis_addr *addr);

void *redisCmd(redisContext *c, const char *format, ...) __attribute__ ((format(printf, 2, 3)));

# endif

