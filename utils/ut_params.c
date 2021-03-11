/*
 * Description: 
 *     History: yangxiaoqiang@viabtc.com, 2018/02/28, create
 */
# include <stdlib.h>
# include <string.h>
# include <ctype.h>
# include "ut_misc.h"
# include "ut_params.h"

static uint32_t dict_params_hash_func(const void *key)
{
    return dict_generic_hash_function(key, strlen(key));
}

static int dict_params_key_compare(const void *key1, const void *key2)
{
    return strcmp(key1, key2);
}

static void *dict_params_dup(const void *obj)
{
    return strdup(obj);
}

static void dict_params_free(void *obj)
{
    free(obj);
}

sds params_url_encode(const char *value, int len)
{
    sds result = sdsempty();
    char hexchars[] = "0123456789ABCDEF";
    while (len--) {
        char c = *value++;
        if ((c < '0' && c != '-' && c != '.') ||
                 (c < 'A' && c > '9') ||
                 (c > 'Z' && c < 'a' && c != '_') ||
                 (c > 'z')) {
            result = sdscat(result, "%");
            result = sdscatprintf(result, "%c", hexchars[c >> 4]);
            result = sdscatprintf(result, "%c", hexchars[c & 15]);
        } else {
            result = sdscatprintf(result, "%c", c);
        }
    }
    return result;
}


sds params_url_decode(const char *value, int len)
{
    sds result = sdsempty();
    while (len--) {
        if (*value == '+') {
            result = sdscat(result, " ");
        } else if (*value == '%' && len >= 2 && isxdigit(*(value + 1)) && isxdigit(*(value + 2))) {
            result = sdscatprintf(result, "%c", hex2int(*(value + 1)) * 16 + hex2int(*(value + 2)));
            value += 2;
            len -= 2;
        } else {
            result = sdscatprintf(result, "%c", *value);
        }
        value++;
    }
    return result;
}

dict_t *params_decode(const char *params_str)
{
    dict_t *params_dict = params_dict_create();
    if (params_dict == NULL) {
        return NULL;
    }

    char *tmp = strdup(params_str);
    char *comment = strchr(tmp, '#');
    if (comment)
        *comment = 0;

    char *param = strtok(tmp, "&");
    while (param) {
        char *sep = strchr(param, '=');
        if (sep) {
            *sep = 0;
            dict_add(params_dict, param, sep + 1);
        } else {
            dict_add(params_dict, param, "");
        }
        param = strtok(NULL, "&");
    }

    free(tmp);
    return params_dict;
}

sds params_encode(dict_t *params_dict)
{
    if (params_dict == NULL) {
        return NULL;
    }

    int count = 0;
    sds result = sdsempty();
    dict_entry *entry = NULL;
    dict_iterator *iter = dict_get_iterator(params_dict);
    while ((entry = dict_next(iter)) != NULL) {
        sds val = params_url_encode(entry->val, strlen(entry->val));
        if (count > 0) {
            result = sdscat(result, "&");
        }
        result = sdscatprintf(result, "%s=", (char *)entry->key);
        result = sdscatsds(result, val);
        sdsfree(val);
        count++;
    }
    dict_release_iterator(iter);
    return result;
}

dict_t *params_dict_create()
{
    dict_types dt;
    memset(&dt, 0, sizeof(dt));
    dt.hash_function = dict_params_hash_func;
    dt.key_compare = dict_params_key_compare;
    dt.key_dup = dict_params_dup;
    dt.key_destructor = dict_params_free;
    dt.val_dup = dict_params_dup;
    dt.val_destructor = dict_params_free;

    return dict_create(&dt, 64);
}

void params_dict_free(dict_t *params_dict)
{
    dict_release(params_dict);
}