/*
 * Description: Bitcoin base58 encode/decode
 *              https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 *     History: yang@haipo.me, 2016/04/04, create
 */

# include <ctype.h>
# include <string.h>
# include <stdint.h>
# include <stdlib.h>
# include <assert.h>

# include "ut_base58.h"
# include "ut_misc.h"

/* All alphanumeric characters except for "0", "I", "O", and "l" */
static const char *base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

sds base58_decode(const char *str)
{
    sds result = sdsempty();
    assert(result != NULL);

    // Skip leading spaces.
    while (*str && isspace(*str)) {
        ++str;
    }

    // Skip leading '1's.
    for (; *str == '1'; ++str) {
        char c = '\0';
        result = sdscatlen(result, &c, 1);
        assert(result != NULL);
    }

    // Allocate enough space in big-endian base256 representation.
    size_t b256_size = strlen(str) * 733 / 1000 + 1; // log(58) / log(256), rounded up.
    uint8_t *b256 = malloc(b256_size);
    assert(b256 != NULL);
    memset(b256, 0, b256_size);

    // Process the characters.
    for (; *str && !isspace(*str); ++str) {
        const char *ch = strchr(base58, *str);
        if (ch == NULL) {
            goto error;
        }

        // Apply "b256 = b256 * 58 + ch".
        int carry = ch - base58;
        for (size_t i = b256_size; i > 0; --i) {
            carry += 58 * b256[i - 1];
            b256[i - 1] = carry % 256;
            carry /= 256;
        }
    }

    // Skip trailing spaces.
    while (isspace(*str)) {
        ++str;
    }
    if (*str != '\0') {
        goto error;
    }

    // Copy result into output vector.
    size_t i = 0;
    while (i < b256_size && b256[i] == 0)
        ++i;
    result = sdscatlen(result, b256 + i, b256_size - i);
    assert(result != NULL);
    free(b256);
    return result;

error:
    free(b256);
    sdsfree(result);
    return NULL;
}


sds base58_encode(const char *mem, size_t len)
{
    sds result = sdsempty();
    assert(result != NULL);

    // Skip leading zeroes.
    size_t pos = 0;
    for (; pos < len && ((uint8_t *)mem)[pos] == '\0'; ++pos) {
        result = sdscat(result, "1");
        assert(result != NULL);
    }

    size_t length = 0;
    size_t b58_size = (len - pos) * 138 / 100 + 1; // log(256) / log(58), rounded up.
    uint8_t *b58 = malloc(b58_size);
    assert(b58 != NULL);
    memset(b58, 0, b58_size);

    // Process the bytes.
    for (; pos < len; ++pos) {
        // Apply "b58 = b58 * 256 + ch".
        int carry = ((uint8_t *)mem)[pos];
        size_t j = 0;
        for (size_t i = b58_size; (carry != 0 || j < length) && (i > 0); --i, ++j) {
            carry += 256 * b58[i - 1];
            b58[i - 1] = carry % 58;
            carry /= 58;
        }
        length = j;
    }

    // Skip leading zeroes in base58 result.
    size_t i = b58_size - length;
    while (i < b58_size && b58[i] == 0)
        ++i;

    // Translate the result into a string.
    for (; i < b58_size; ++i) {
        result = sdscatlen(result, base58 + b58[i], 1);
    }

    free(b58);
    return result;
}

sds address2sig(const char *address)
{
    sds r = base58_decode(address);

    if (r == NULL){
        return NULL;
    }

    if (sdslen(r) != 25) {
        sdsfree(r);
        return NULL;
    }
    sds result = sdsnewlen(r + 1, sdslen(r) - 5);
    sdsfree(r);
    return result;
}

sds sig2address(uint8_t version, const char *sig)
{
    char tmp[25];
    tmp[0] = version;
    memcpy(tmp + 1, sig, 20);
    char hash[32];
    sha256d(tmp, 21, hash);
    memcpy(tmp + 21, hash, 4);
    return base58_encode(tmp, 25);
}

sds zec_address2sig(const char *address)
{
    sds r = base58_decode(address);
    if (r == NULL){
        return NULL;
    }

    if (sdslen(r) != 26) {
        sdsfree(r);
        return NULL;
    }
    sds result = sdsnewlen(r + 2, sdslen(r) - 6);
    sdsfree(r);
    return result;
}

sds zec_sig2address(uint8_t prefix, uint8_t version, const char *sig)
{
    char tmp[26];
    tmp[0] = prefix;
    tmp[1] = version;
    memcpy(tmp + 2, sig, 20);
    char hash[32];
    sha256d(tmp, 22, hash);
    memcpy(tmp + 22, hash, 4);
    return base58_encode(tmp, 26);
}

