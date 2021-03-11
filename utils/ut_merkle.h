/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/13, create
 */

# ifndef _UT_MERKLE_H_
# define _UT_MERKLE_H_

# include <stddef.h>
# include "ut_sds.h"

sds *get_merkle_branch(sds *nodes, size_t node_count, size_t *branch_count);
void get_merkle_root(char *first, sds *branch, size_t branch_count);
sds get_merkle_root_custom(sds *merkle_leaf, int merkle_size);
sds *get_merkle_branch_custom(sds *merkle_leaf, int merkle_size, int merkle_index, int *branch_count);

# endif

