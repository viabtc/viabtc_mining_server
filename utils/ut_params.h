/*
 * Description: 
 *     History: yangxiaoqiang@viabtc.com, 2018/02/28, create
 */
# ifndef _UT_PARAMS_H_
# define _UT_PARAMS_H_

# include "ut_sds.h"
# include "ut_dict.h"

dict_t *params_dict_create();
void params_dict_release(dict_t *params_dict);

dict_t *params_decode(const char *params_str);
sds params_encode(dict_t *params_dict);

sds params_url_encode(const char *value, int len);
sds params_url_decode(const char *value, int len);
#endif