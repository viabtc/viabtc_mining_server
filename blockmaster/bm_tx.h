/*
 * Description: 
 *     History: yang@haipo.me, 2016/10/22, create
 */

# ifndef _BM_TX_H_
# define _BM_TX_H_

int init_tx(void);
sds get_tx_info(void);
sds get_tx_data(void *key);
void update_tx(void *hash, void *tx, size_t tx_size);
int decode_block(void *block, size_t block_size, char *block_head, sds *coinbase_tx, uint32_t *tx_count, sds *tx_info);

# endif

