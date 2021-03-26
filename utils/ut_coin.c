/*
 * Description: 
 *     History: yang@haipo.me, 2016/03/31, create
 */

# include <stdlib.h>
# include <string.h>
# include <assert.h>
# include <stdbool.h>

# include "ut_coin.h"
# include "ut_misc.h"
# include "ut_log.h"

static void append_node(coin_rpc *rpc, coin_daemon_node *node)
{
    if (rpc->list == NULL) {
        rpc->list = node;
        return;
    }
    coin_daemon_node *curr = rpc->list;
    while (curr->next != NULL) {
        curr = curr->next;
    }
    curr->next = node;
    node->prev = curr;
}

static void move_to_front(coin_rpc *rpc, coin_daemon_node *node)
{
    if (node == rpc->list)
        return;
    node->prev->next = node->next;
    if (node->next) {
        node->next->prev = node->prev;
    }
    node->next = rpc->list;
    node->prev = NULL;
    rpc->list->prev = node;
    rpc->list = node;
}

coin_rpc *coin_rpc_create(coin_rpc_cfg *cfg)
{
    if (cfg->count == 0)
        return NULL;

    coin_rpc *rpc = malloc(sizeof(coin_rpc));
    memset(rpc, 0, sizeof(coin_rpc));
    assert(rpc != NULL);
    rpc->name = strdup(cfg->name);
    rpc->count = cfg->count;
    for (uint32_t i = 0; i < rpc->count; ++i) {
        coin_daemon_node *node = malloc(sizeof(coin_daemon_node));
        assert(node != NULL);
        memset(node, 0, sizeof(coin_daemon_node));
        memcpy(&node->daemon, &cfg->arr[i], sizeof(coin_daemon));
        append_node(rpc, node);
    }

    return rpc;
}

void coin_rpc_release(coin_rpc *rpc)
{
    coin_daemon_node *curr = rpc->list;
    coin_daemon_node *next;
    while (curr) {
        next = curr->next;
        free(curr);
        curr = next;
    }
    free(rpc);
}

static size_t post_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    sds *reply = userdata;
    *reply = sdscatlen(*reply, ptr, size * nmemb);
    return size * nmemb;
}

json_t *coin_rpc_cmd(coin_rpc *rpc, double timeout, const char *method, json_t *params)
{
    json_t *data = json_object();
    assert(data != NULL);
    json_object_set_new(data, "jsonrpc", json_string("2.0"));
    json_object_set_new(data, "method", json_string(method));
    json_object_set_new(data, "id", json_integer((int64_t)(current_timestamp() * 1000)));

    if (params) {
        json_object_set(data, "params", params);
    } else {
        json_object_set_new(data, "params", json_array());
    }
    char *post_data = json_dumps(data, 0);
    json_decref(data);
    if (post_data == NULL) {
        return NULL;
    }
    
    coin_daemon_node *curr = rpc->list;
    while (curr) {
        sds url = sdsempty();
        url = sdscatprintf(url, "http://%s:%d/", curr->daemon.host, curr->daemon.port);
        sds auth = sdsempty();
        auth = sdscatprintf(auth, "%s:%s", curr->daemon.user, curr->daemon.pass);

        sds reply = sdsempty();
        CURL *curl = curl_easy_init();
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_USERPWD, auth);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(post_data));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, post_write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &reply);
        if (timeout > 0) {
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)(timeout * 1000));
        }
        sdsfree(url);
        sdsfree(auth);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        CURLcode ret = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        if (ret != CURLE_OK) {
            log_error("coin rpc curl fail: %d", ret);
            curl_easy_cleanup(curl);
            sdsfree(reply);
            curr = curr->next;
            continue;
        }
        curl_easy_cleanup(curl);
        json_t *r = json_loads(reply, 0, NULL);
        if (r == NULL) {
            log_error("json decode reply fail");
            sdsfree(reply);
            curr = curr->next;
            continue;
        }
        sdsfree(reply);

        json_t *error = json_object_get(r, "error");
        if (error != NULL && !json_is_null(error)) {
            log_error("coin rpc: %s@%s:%d error: %lld: %s", method,
                    curr->daemon.host, curr->daemon.port,
                    json_integer_value(json_object_get(error, "code")),
                    json_string_value(json_object_get(error, "message")));
            json_decref(r);
            curr = curr->next;
            continue;
        }

        json_t *result = json_object_get(r, "result");
        if (!result) {
            log_error("coin rpc: %s result null", method);
            json_decref(r);
            curr = curr->next;
            continue;
        }

        move_to_front(rpc, curr);
        free(post_data);
        json_incref(result);
        json_decref(r);

        return result;
    }

    free(post_data);
    return NULL;
}

json_t *coin_get_json(coin_rpc *rpc, double timeout, const char *path, long *http_code)
{
    coin_daemon_node *curr = rpc->list;
    while (curr) {
        sds url = sdsempty();
        url = sdscatprintf(url, "http://%s:%d/%s", curr->daemon.host, curr->daemon.port, path);
        sds auth = sdsempty();
        auth = sdscatprintf(auth, "%s:%s", curr->daemon.user, curr->daemon.pass);
        sds reply = sdsempty();

        CURL *curl = curl_easy_init();
        curl_easy_setopt(curl, CURLOPT_URL, url);
        //some special api need
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERPWD, auth);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, post_write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &reply);
        if (timeout > 0) {
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)(timeout * 1000));
        }

        sdsfree(url);
        sdsfree(auth);

        CURLcode ret = curl_easy_perform(curl);
        if (ret != CURLE_OK) {
            log_error("rpc curl fail: %d", ret);
            curl_easy_cleanup(curl);
            sdsfree(reply);
            curr = curr->next;
            continue;
        }
        curl_easy_cleanup(curl);

        ret = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE , http_code);
        if (ret != CURLE_OK) {
            log_error("get http code fail: %d", ret);
            sdsfree(reply);
            curr = curr->next;
            continue;
        }

        move_to_front(rpc, curr);
        json_t *result = json_loads(reply, 0, NULL);
        if (result == NULL) {
            log_error("json decode reply fail");
            sdsfree(reply);
            curr = curr->next;
            continue;
        }
        return result;
    }
    return NULL;
}

json_t *coin_post(coin_rpc *rpc, double timeout, const char *path, const char *data, long *http_code)
{
    coin_daemon_node *curr = rpc->list;
    while (curr) {
        sds url = sdsempty();
        url = sdscatprintf(url, "http://%s:%d/%s", curr->daemon.host, curr->daemon.port, path);
        sds auth = sdsempty();
        auth = sdscatprintf(auth, "%s:%s", curr->daemon.user, curr->daemon.pass);
        sds reply = sdsempty();

        CURL *curl = curl_easy_init();
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERPWD, auth);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(data));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, post_write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &reply);
        if (timeout > 0) {
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)(timeout * 1000));
        }

        sdsfree(url);
        sdsfree(auth);

        CURLcode ret = curl_easy_perform(curl);
        if (ret != CURLE_OK) {
            log_error("rpc curl fail: %d", ret);
            curl_easy_cleanup(curl);
            sdsfree(reply);
            curr = curr->next;
            continue;
        }
        curl_easy_cleanup(curl);

        ret = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE , http_code);
        if (ret != CURLE_OK) {
            log_error("get http code fail: %d", ret);
            sdsfree(reply);
            curr = curr->next;
            continue;
        }

        move_to_front(rpc, curr);
        json_t *result = json_loads(reply, 0, NULL);
        if (result == NULL) {
            log_error("json decode reply fail: %s", reply);
            sdsfree(reply);
            curr = curr->next;
            continue;
        }
        return result;
    }
    return NULL;
}

