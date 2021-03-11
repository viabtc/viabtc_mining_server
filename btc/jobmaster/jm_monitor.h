# ifndef _JM_MONITOR_H_
# define _JM_MONITOR_H_

int init_monitor(void);

void inc_submit_main_success(void);
void inc_submit_main_error(void);
void inc_submit_aux_success(void);
void inc_submit_aux_error(void);
void inc_spv_total(void);
void inc_spv_timeout(void);
void inc_recv_out_height(void);
int send_jobmaster_update(uint32_t height);

# endif
