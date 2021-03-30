# ifndef _BP_MONITOR_H_
# define _BP_MONITOR_H_

int init_monitor_server(void);

void inc_p2p_success(const char *cmd);
void inc_p2p_error(const char *cmd);

void inc_submit_block_success(void);
void inc_submit_block_error(void);
void inc_update_block_success(void);
void inc_update_block_error(void);

# endif
