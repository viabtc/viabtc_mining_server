/*
 * Description: 
 *     History: yang@haipo.me, 2016/07/20, create
 */

# ifndef _JM_AUX_H_
# define _JM_AUX_H_

# include <stdint.h>
# include <jansson.h>
# include "jm_config.h"

typedef struct aux_info {
    int         height;
    int         chain_id;
    int         merkle_index;
    time_t      update_time;
    sds         address;
    coin_rpc    *coin;
    json_t      *block;
} aux_info;

dict_t *aux_dict;
int32_t get_merkle_size();
int init_aux(void);
int on_aux_blocknotify(const char *aux_name);
int submit_aux_block(const char *aux_name, const char *aux_hash, const char *aux_pow);

# endif