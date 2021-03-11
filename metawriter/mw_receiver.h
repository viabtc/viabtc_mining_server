/*
 * Description: 
 *     History: yang@haipo.me, 2016/12/04, create
 */

# ifndef _MW_RECEIVER_H_
# define _MW_RECEIVER_H_

int init_receiver(void);
sds list_trust();
int load_trust(const char *filename);

# endif

