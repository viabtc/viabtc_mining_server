# ifndef _BM_REQUEST_H_
# define _BM_REQUEST_H_

typedef int (*request_callback)(json_t *reply);

int init_request(void);
int init_blockmaster_config(void);
int update_blockmaster_config(request_callback callback);

# endif

