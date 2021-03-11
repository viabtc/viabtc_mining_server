# ifndef _BM_MONITOR_H_
# define _BM_MONITOR_H_

int init_monitor_server(void);

void inc_submit_block_success(void);
void inc_submit_block_error(void);
void inc_thin_block_submit_update_success(uint32_t cmd);
void inc_thin_block_submit_update_error(uint32_t cmd);
void inc_thin_block_tx_success(void);
void inc_thin_block_tx_error(void);

# endif