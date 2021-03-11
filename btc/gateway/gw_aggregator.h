/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/02, create
 */

# ifndef _GW_AGGREGATOR_H_
# define _GW_AGGREGATOR_H_

# include <stdint.h>

# define AGGREG_MAGIC_NUM 0xe7d5c474

# define AGGREG_CMD_NEW_BLOCK 1
# define AGGREG_CMD_NEW_SHARE 2
# define AGGREG_CMD_NEW_EVENT 3
# define AGGREG_CMD_KEY_VALUE 4

int init_aggregator(void);
void aggregator_flush(void);

# pragma pack(1)
struct aggreg_head {
    uint32_t magic;
    uint32_t pkg_size;
    uint32_t command;
};
# pragma pack(0)

# endif

