/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/18, create
 */

# ifndef _BM_BLOCK_H_
# define _BM_BLOCK_H_

# include <stddef.h>

int init_block(void);
int on_blocknotify(void);
int on_submit_block(void *data, size_t size);
int on_update_block(void *data, size_t size);
bool is_block_exist(char *block_hash);
int get_outer_height(void);
int get_self_height(void);

# endif

