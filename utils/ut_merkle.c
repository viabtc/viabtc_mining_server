/*
 * Description: 
 *     History: yang@haipo.me, 2016/04/13, create
 */

# include <stdlib.h>
# include <string.h>
# include <math.h>

# include "ut_merkle.h"
# include "ut_misc.h"

static void merkle_join(const char *hash1, const char *hash2, char *hash)
{
    char tmp[64];
    memcpy(tmp, hash1, 32);
    memcpy(tmp + 32, hash2, 32);
    sha256d(tmp, sizeof(tmp), hash);
}

sds *get_merkle_branch(sds *nodes, size_t node_count, size_t *branch_count)
{
    size_t list_len = node_count;
    sds *list = malloc(sizeof(sds) * (list_len + 1));
    for (size_t i = 0; i < list_len; ++i) {
        if (sdslen(nodes[i]) != 32)
            return NULL;
        list[i] = sdsdup(nodes[i]);
    }

    sds result = sdsempty();
    size_t result_count = 0;
    while (list_len) {
        result = sdscatlen(result, list[0], sdslen(list[0]));
        result_count += 1;

        if (list_len == 1)
            break;
        if ((list_len - 1) % 2 != 0) {
            list[list_len] = sdsdup(list[list_len - 1]);
            list_len += 1;
        }

        size_t step = list_len / 2;
        sds *new_list = malloc(sizeof(sds) * (step + 1));
        for (size_t i = 0; i < step; ++i) {
            char hash[32];
            merkle_join(list[1 + i * 2], list[1 + i * 2 + 1], hash);
            new_list[i] = sdsnewlen(hash, sizeof(hash));
        }

        for (size_t i = 0; i < list_len; ++i) {
            sdsfree(list[i]);
        }
        free(list);

        list = new_list;
        list_len = step;
    }

    for (size_t i = 0; i < list_len; ++i) {
        sdsfree(list[i]);
    }
    free(list);

    sds *branch = malloc(sizeof(sds) * result_count);
    for (size_t i = 0; i < result_count; ++i) {
        branch[i] = sdsnewlen(result + i * 32, 32);
    }
    sdsfree(result);
    *branch_count = result_count;

    return branch;
}

void get_merkle_root(char *first, sds *branch, size_t branch_count)
{
    for (uint32_t i = 0; i < branch_count; ++i) {
        merkle_join(first, branch[i], first);
    }
}

sds get_merkle_root_custom(sds *merkle_leaf, int merkle_size)
{
    for (size_t i = 0; i < merkle_size; ++i) {
        if (sdslen(merkle_leaf[i]) != 32)
            return NULL;
    }

    if (merkle_size == 1) {
        return sdsnewlen(merkle_leaf[0], 32);
    }

    size_t list_len = merkle_size;
    sds *list = malloc(sizeof(sds) * list_len);
    for (size_t i = 0; i < list_len; ++i) {
        list[i] = sdsdup(merkle_leaf[i]);
    }

    int len = merkle_size / 2;
    while (len >= 1) {
        for (int i = 0; i < len; i++) {
            sds hash1 = list[i * 2];
            sds hash2 = list[i * 2 + 1];
            char hash[32];
            merkle_join(hash1, hash2, hash);
            list[i] = sdsnewlen(hash, sizeof(hash));
            sdsfree(hash1);
            sdsfree(hash2);
        }
        len /= 2;
    }

    sds merkle_root = list[0];
    free(list);
    return merkle_root;
}

sds *get_merkle_branch_custom(sds *merkle_leaf, int merkle_size, int merkle_index, int *branch_count)
{
    for (size_t i = 0; i < merkle_size; ++i) {
        if (sdslen(merkle_leaf[i]) != 32)
            return NULL;
    }
    
    int level = (int)(log10(merkle_size) / log10(2));
    *branch_count = level;
    sds *result = malloc(sizeof(sds) * level);
    if (merkle_size == 1) {
        result[0] = sdsnewlen(NULL, 32);
        return result;
    }

    size_t list_len = merkle_size;
    sds *list = malloc(sizeof(sds) * list_len);
    for (size_t i = 0; i < list_len; ++i) {
        list[i] = sdsdup(merkle_leaf[i]);
    }

    int len = merkle_size / 2;
    int branch_index = 0;
    while (len >= 1) {
        for (int i = 0; i < len; i++) {
            if (merkle_index != i * 2 && merkle_index != i * 2 + 1) {
                sds hash1 = list[i * 2];
                sds hash2 = list[i * 2 + 1];
                char hash[32];
                merkle_join(hash1, hash2, hash);
                list[i] = sdsnewlen(hash, 32);
                sdsfree(hash1);
                sdsfree(hash2);
            } else {
                sds hash1 = list[i * 2];
                sds hash2 = list[i * 2 + 1];
                if (merkle_index == i * 2 + 1) {
                    result[branch_index] = sdsnewlen(hash1, 32);
                } else {
                    result[branch_index] = sdsnewlen(hash2, 32);
                }
                list[i] = sdsnewlen(result[branch_index], 32);
                sdsfree(hash1);
                sdsfree(hash2);
                branch_index++;
            }
        }
        merkle_index /= 2;
        len /= 2;
    }

    sdsfree(list[0]);
    free(list);
    return result;
}

