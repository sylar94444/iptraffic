#include "process.h"
#include "log.h"
#include "util.h"
#include "transmit.h"
#include "iptraffic.h"
#include "hash.h"

struct http_response_element_s g_resp_element_table[REDIRECT_TYPE_MAX];
extern struct cycle_s g_cycle;

void init_resp_table()
{
    int type = 0;
    for (type = 0; type < REDIRECT_TYPE_MAX; type++)
    {
        switch(type)
        {
            case REDIRECT_TYPE_REFRESH:
            {
                g_resp_element_table[type].header = HTTP_RESP_200OK_HEADER;
                g_resp_element_table[type].header_len = strlen(HTTP_RESP_200OK_HEADER);
                g_resp_element_table[type].resp_body_start = HTTP_RESP_REFRESH_BEGIN;
                g_resp_element_table[type].resp_body_start_len = strlen(HTTP_RESP_REFRESH_BEGIN);
                g_resp_element_table[type].resp_body_middle= "";
                g_resp_element_table[type].resp_body_middle_len = 0;
                g_resp_element_table[type].resp_body_end = HTTP_RESP_REFRESH_END;
                g_resp_element_table[type].resp_body_end_len = strlen(HTTP_RESP_REFRESH_END);
                break;
            }
            case REDIRECT_TYPE_IFRAME:
            {
                g_resp_element_table[type].header = HTTP_RESP_200OK_HEADER;
                g_resp_element_table[type].header_len = strlen(HTTP_RESP_200OK_HEADER);
                g_resp_element_table[type].resp_body_start = HTTP_RESP_IFRAME_BEGIN;
                g_resp_element_table[type].resp_body_start_len = strlen(HTTP_RESP_IFRAME_BEGIN);
                g_resp_element_table[type].resp_body_middle= "";
                g_resp_element_table[type].resp_body_middle_len = 0;
                g_resp_element_table[type].resp_body_end = HTTP_RESP_IFRAME_END;
                g_resp_element_table[type].resp_body_end_len = strlen(HTTP_RESP_IFRAME_END);
                break;
            }
            case REDIRECT_TYPE_NOREFERER:
            {
                g_resp_element_table[type].header = HTTP_RESP_200OK_HEADER;
                g_resp_element_table[type].header_len = strlen(HTTP_RESP_200OK_HEADER);
                g_resp_element_table[type].resp_body_start = HTTP_RESP_NOREFERER_BEGIN;
                g_resp_element_table[type].resp_body_start_len = strlen(HTTP_RESP_NOREFERER_BEGIN);
                g_resp_element_table[type].resp_body_middle= "";
                g_resp_element_table[type].resp_body_middle_len = 0;
                g_resp_element_table[type].resp_body_end = HTTP_RESP_NOREFERER_END;
                g_resp_element_table[type].resp_body_end_len = strlen(HTTP_RESP_NOREFERER_END);
                break;
            }
            case REDIRECT_TYPE_302:
            {
                g_resp_element_table[type].header = HTTP_RESP_302_HEADER;
                g_resp_element_table[type].header_len = strlen(HTTP_RESP_302_HEADER);
                g_resp_element_table[type].resp_body_start = "";
                g_resp_element_table[type].resp_body_start_len = 0;
                g_resp_element_table[type].resp_body_middle= "";
                g_resp_element_table[type].resp_body_middle_len = 0;
                g_resp_element_table[type].resp_body_end = "";
                g_resp_element_table[type].resp_body_end_len = 0;
                break;
            }
            case REDIRECT_TYPE_JS_IFRAME:
            {
                g_resp_element_table[type].header = HTTP_RESP_200OK_HEADER;
                g_resp_element_table[type].header_len = strlen(HTTP_RESP_200OK_HEADER);
                g_resp_element_table[type].resp_body_start = HTTP_RESP_JS_IFRAME_BEGING;
                g_resp_element_table[type].resp_body_start_len = strlen(HTTP_RESP_JS_IFRAME_BEGING);
                g_resp_element_table[type].resp_body_middle= HTTP_RESP_JS_IFRAME_MIDDLE;
                g_resp_element_table[type].resp_body_middle_len = strlen(HTTP_RESP_JS_IFRAME_MIDDLE);
                g_resp_element_table[type].resp_body_end = HTTP_RESP_JS_IFRAME_END;
                g_resp_element_table[type].resp_body_end_len = strlen(HTTP_RESP_JS_IFRAME_END);
                break;
            }
            case REDIRECT_TYPE_JS:
            {
                g_resp_element_table[type].header = HTTP_RESP_JS_HEADER;
                g_resp_element_table[type].header_len = strlen(HTTP_RESP_JS_HEADER);
                g_resp_element_table[type].resp_body_start = HTTP_RESP_JS_BEGING;
                g_resp_element_table[type].resp_body_start_len = strlen(HTTP_RESP_JS_BEGING);
                g_resp_element_table[type].resp_body_middle= HTTP_RESP_JS_MIDDLE;
                g_resp_element_table[type].resp_body_middle_len = strlen(HTTP_RESP_JS_MIDDLE);
                g_resp_element_table[type].resp_body_end = "";
                g_resp_element_table[type].resp_body_end_len = 0;
                break;
            }
            case REDIRECT_TYPE_JSBODY:
            {
                g_resp_element_table[type].header = HTTP_RESP_200OK_HEADER;
                g_resp_element_table[type].header_len = strlen(HTTP_RESP_200OK_HEADER);
                g_resp_element_table[type].resp_body_start = HTTP_RESP_JSBODY_BEGING;
                g_resp_element_table[type].resp_body_start_len = strlen(HTTP_RESP_JSBODY_BEGING);
                g_resp_element_table[type].resp_body_middle= "";
                g_resp_element_table[type].resp_body_middle_len = 0;
                g_resp_element_table[type].resp_body_end = HTTP_RESP_JSBODY_END;
                g_resp_element_table[type].resp_body_end_len = strlen(HTTP_RESP_JSBODY_END);
                break;
            }
            case REDIRECT_TYPE_JSON:
            {
                g_resp_element_table[type].header = HTTP_RESP_200OK_JSON_HEADER;
                g_resp_element_table[type].header_len = strlen(HTTP_RESP_200OK_JSON_HEADER);
                g_resp_element_table[type].resp_body_start = "";
                g_resp_element_table[type].resp_body_start_len = 0;
                g_resp_element_table[type].resp_body_middle= "";
                g_resp_element_table[type].resp_body_middle_len = 0;
                g_resp_element_table[type].resp_body_end = "";
                g_resp_element_table[type].resp_body_end_len = 0;
                break;
            }
            default:
            {
                break;
            }
        }
    }
    
}

struct http_request_s* http_new_request(void)
{
    struct http_request_s *r = NULL;
    r = MALLOC(http_request_t, 1);

    r->host = (char *)MALLOC(char, MAX_HOST_LEN);
    r->host_len = 0;
    r->referer = (char *)MALLOC(char, MAX_REF_LEN);
    r->referer_len = 0;
    r->uri = (char *)MALLOC(char, MAX_URI_LEN);
    r->uri_len = 0;
    r->url = (char *)MALLOC(char, MAX_URL_LEN);
    r->url_len = 0;
    r->user_agent = (char *)MALLOC(char, MAX_AGENT_LEN);
    r->user_agent_len = 0;
    r->cookie = (char *)MALLOC(char, MAX_COOKIE_LEN);
    r->cookie_len = 0;
 
    return r;
}

void http_free_request(struct http_request_s *r)
{
    FREE(r->host);
    FREE(r->cookie);
    FREE(r->referer);
    FREE(r->uri);
    FREE(r->url);
    FREE(r->user_agent);
    FREE(r);
}

struct http_response_s* http_new_response(void)
{
    struct http_response_s *p = NULL;
    p = MALLOC(http_response_t, 1);

    p->url = (char *)MALLOC(char, MAX_URL_LEN);
    p->cookie = (char *)MALLOC(char, MAX_COOKIE_LEN);
    p->payload = MALLOC(u_char,MAX_PAYLOAD_LEN);
    
    return p;
}

void http_free_response(struct http_response_s *p)
{
    FREE(p->cookie);
    FREE(p->url);
    FREE(p->payload);
    FREE(p);
}

int http_parse_get(struct http_request_s *r, unsigned char* data)
{
    /* rollback */
    r->host_len = 0;
    r->uri_len = 0;
    r->url_len = 0;
    r->referer_len = 0;
    r->cookie_len = 0;    
    r->user_agent_len = 0;
    
    char* buf = (char *)data;
    char *sep = NULL;
    int len = 0, flag = 0;
    unsigned int cnt = 0;
    //buf += 4;
    
    //detect URI
    sep = strchr(buf, ' ');
    if (sep == 0)
        return IPTRAFFIC_FUNC_ERROR;
    
    len = sep - buf;
    
    if (len <= MAX_URI_LEN)
    {
        r->uri_len = len;
        *(r->uri + len) = '\0';
        memcpy(r->uri, buf, len);
    }
    
    //start parse header
    buf = strstr(buf, "\r\n");
    while(buf != 0 && cnt < 6)
    {
        buf = buf + 2;
        
        if ( (*buf != '\0' && *(buf + 1) != '\0' && check_crlf(buf, 2)))
            break;
        
        sep = strstr(buf, "\r\n");
        if (sep == 0)
        {
            flag = 1;
            
            sep = buf + strlen(buf);
        }
        
        switch(buf[0])
        {
            case 'h':
            case 'H':
                if ((sep - buf > 7) && (0 == strncasecmp("Host:", buf, 5)))            //Host: man.chinaunix.net
                {
                    len = (buf[5] == ' ') ? 6 : 5;
                    buf = buf + len;
                    
                    len = sep - buf;
                    
                    if (len <= MAX_HOST_LEN)
                    {
                        r->host_len = len;
                        *(r->host + len) = '\0';
                        memcpy(r->host, buf, len);
                    }
                    
                    cnt++;
                }
                break;
            case 'u':    
            case 'U':
                if ((sep - buf > 12) && (0 == strncasecmp("User-Agent:", buf, 11)))    //User-Agent: Mozilla/5.0 Firefox/21.0
                {
                    len = (buf[11] == ' ') ? 12 : 11;
                    buf = buf + len;
                    
                    len = sep - buf;
                    
                    if (len <= MAX_AGENT_LEN)
                    {
                        r->user_agent_len = len;
                        *(r->user_agent + len) = '\0';
                        memcpy(r->user_agent, buf, len);
                    }
                    
                    cnt++;
                }
                break;
            case 'r':     
            case 'R':
                if ((sep - buf > 10) && (0 == strncasecmp("Referer:", buf, 8)))    //Referer: http://man.chinaunix.net/develop/c&c++/linux_c/default.htm
                {
                    len = (buf[8] == ' ') ? 9 : 8;
                    buf = buf + len;
                    
                    len = sep - buf;
                    
                    if (len < MAX_REF_LEN)
                    {
                        r->referer_len = len;
                        *(r->referer + len) = '\0';
                        memcpy(r->referer, buf, len);
                    }
                    
                    cnt++;
                }
                break;
            case 'c':    
            case 'C':
                if ((sep - buf > 9) && (0 == strncasecmp("Cookie:", buf, 7)))    //Cookie: __utma=225341893.1493557647;
                {
				    len = (buf[7] == ' ') ? 8 : 7;
                    buf = buf + len;
                    
                    len = sep - buf;
                    
                    if (len < MAX_COOKIE_LEN)
                    {
                        r->cookie_len = len;
                        *(r->cookie + len) = '\0';
                        memcpy(r->cookie, buf, len);
                    }
                    
                    cnt++;
                }
                break;
        }
        
        if (flag == 1)
            break;
        
        buf = sep;
    }

    strcpy(r->url, r->host);
    if (strcmp(r->uri, "/") != 0) 
    {
       strcat(r->url, r->uri);
    }
    r->url_len = strlen(r->url);
    
    return IPTRAFFIC_FUNC_SUCCESS;
}

#if 0
static int http_detect_request_type(const char *uri, int uri_len)
{
    char* buf = (unsigned char*)uri;
	char *sep = NULL;
    
    buf = (unsigned char*)uri + uri_len - 3;
    
    //tar/gz/tgz/zip/Z/7z/rpm/deb/ps/dvi/pdf/smi/png/jpg/jpeg/bmp/tiff/gif/mov/avi/mpeg/mpg/mp3/qt/wav/ram/rm/rmvb/jar/java/class/diff/doc/docx/xls/ppt/mdb/rtf/exe/pps/so/psd/css/js/ico/dll/bz2/rar
	if (!strncmp(buf, "gif", 3) || !strncmp(buf, ".js", 3) || !strncmp(buf, "jpg", 3) || !strncmp(buf, "png", 3)
        || !strncmp(buf, "bmp", 3) || !strncmp(buf, "zip", 3) || !strncmp(buf, "rar", 3) || !strncmp(buf, "doc", 3)
        || !strncmp(buf, "xls", 3) || !strncmp(buf, "swf", 3) || !strncmp(buf, "css", 3) || !strncmp(buf, "ico", 3)
        || !strncmp(buf, "flv", 3) || !strncmp(buf, "exe", 3) || !strncmp(buf, "tar", 3) || !strncmp(buf, "dll", 3)
        || !strncmp(buf, "tgz", 3) || !strncmp(buf, "rpm", 3) || !strncmp(buf, "avi", 3) || !strncmp(buf, "rtf", 3)
        || !strncmp(buf, "xml", 3) || !strncmp(buf, "mpg", 3) || !strncmp(buf, "mp4", 3) || !strncmp(buf, "m4v", 3)
        || !strncmp(buf, "ppt", 3) || !strncmp(buf, "psd", 3) || !strncmp(buf, "wmv", 3) || !strncmp(buf, "peg", 3))
	{
		return IPTRAFFIC_FUNC_ERROR;
	}
    
	//detect URI
	sep = strchr(uri, '.');
	if (sep == 0)
		return IPTRAFFIC_FUNC_SUCCESS;
    
	buf = sep + 1;
	if (*buf == '\0' || *(buf + 1) == '\0')
		return IPTRAFFIC_FUNC_SUCCESS;
    
	if (*(buf + 2) == '\0')
		return IPTRAFFIC_FUNC_SUCCESS;
    
    //jpg/gif/png/bmp/zip/rar/doc/xls/swf/css/ico ---just match lower case
	if (!strncmp(buf, "js", 2) || !strncmp(buf, "jpg", 3) || !strncmp(buf, "gif", 3) || !strncmp(buf, "png", 3)
        || !strncmp(buf, "bmp", 3) || !strncmp(buf, "zip", 3) || !strncmp(buf, "rar", 3) || !strncmp(buf, "flv", 3)
        || !strncmp(buf, "doc", 3) || !strncmp(buf, "css", 3) || !strncmp(buf, "swf", 3) || !strncmp(buf, "ico", 3)
        || !strncmp(buf, "xml", 3))
	{
		return IPTRAFFIC_FUNC_ERROR;
	}
    
	return IPTRAFFIC_FUNC_SUCCESS;
}
#endif

static inline char * detect_cookie_ourselves(struct http_request_s* r, char *keyword)
{
    char *p = NULL;
    
    if (r->cookie_len > 0)
    {
        p = strstr(r->cookie, keyword);
    }

    return p;
}

static inline BOOL detect_filter_useragent(u_char type, regex_t *reg, struct http_request_s* r)
{
    int status = 0;
    
    /* 由外围保证UA  的存在*/ 
    status = regexec(reg, r->user_agent, 0, NULL, 0);
    if (REG_NOMATCH == status)
    {
        if (FILTER_NOMATCHED == type)
        {
            return TRUE;
        }
    }
    else
    {
        if (FILTER_MATCHED == type)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static inline BOOL detect_filter_referer(u_char type, regex_t *reg, struct http_request_s* r)
{
    int status = 0;

    if (r->referer_len> 0)
    {
        status = regexec(reg, r->referer, 0, NULL, 0);
        if (REG_NOMATCH == status)
        {
            if (FILTER_NOMATCHED == type)
            {
                return TRUE;
            }
        }
        else
        {
            if (FILTER_MATCHED == type)
            {
                return TRUE;
            }
        }
    }
    else
    {
        if (FILTER_NOMATCHED == type)
        {
            return TRUE;
        }
    }
    
    return FALSE;
}

static inline BOOL detect_filter_whitelist(u_char type, struct filter_s *filter, struct http_request_s* r)
{
    int status = 0;

    switch(type)
    {
        case FILTER_NONE:
            {
                /* 没有设置标志位，默认白名单策略命中需要替换 */
                return FALSE;
            }
        case FILTER_URL:
            {
                status = regexec(&(filter->white_url), r->url, 0, NULL, 0);
                if (REG_NOMATCH == status)
                {
                    return FALSE;
                }
                break;
            }
        case FILTER_REFERER:
            {
                if(r->referer_len <= 0)
                {
                    return FALSE;
                }
                status = regexec(&(filter->white_referer), r->referer, 0, NULL, 0);
                if (REG_NOMATCH == status)
                {
                    return FALSE;
                }
                break;
            }
        case FILTER_ALL:
            {
                if((regexec(&(filter->white_url), r->url, 0, NULL, 0)==REG_NOMATCH)&&((r->referer_len<=0)||(regexec(&(filter->white_referer), r->referer, 0, NULL, 0)==REG_NOMATCH)))
                {
                    return FALSE;
                }
                break;
            }
        default:
            {
                break;
            }
    }
    
    return TRUE;    
}

static inline int build_url_repled(int dest_index, struct rule_entry_s *rule, char *req_url, char* url_repled)
{
    int replace_flag = rule->type_repled_pos;    /* 0-整体替换，>0-替换部分字段 */
    char *p_dst_page = rule->dest_pages[dest_index];
    char *p_url_repled = url_repled;
    int offset = 0;
    int str_length = 0;
    int pre_pos_num = 0;
    int pos_num = 0;
    char dst_page_element[256] = {0};
    char *p_dst_page_element = NULL;
        
    
    /* 用以替换URL中间字段 */
    if (replace_flag > 0)
    {
        /* 兼容现有配置，pos>0且dst_page中没有<> */
        if (NULL==strchr(p_dst_page, '<'))
        {
            str_length = rule->subs_src_page[replace_flag].rm_so;
            if(str_length == -1)
            {
                /* 策略配置错误*/
                return IPTRAFFIC_FUNC_ERROR;
            }
            memcpy(url_repled, req_url, str_length);
            url_repled[str_length] = '\0';
            
            strcat(url_repled, rule->dest_pages[dest_index]);
            
            strcat(url_repled, req_url+rule->subs_src_page[replace_flag].rm_eo);

            return IPTRAFFIC_FUNC_SUCCESS;
        }
        
        /* 拆分dest_page字符串，获取替换位置 */
        while((p_dst_page=strchr(p_dst_page, '<')))
        {   
            sscanf(p_dst_page, "<%d%s", &pos_num, dst_page_element);

            /* 策略配置错误*/
            if(pre_pos_num > pos_num)
            {
                errlog("Dest_page pos index is wrong:%s",rule->dest_pages[dest_index]);
                return IPTRAFFIC_FUNC_ERROR;
            }
            pre_pos_num = pos_num;

            /* 刨除> */
            p_dst_page_element  = ignore_space(dst_page_element+1);
            
            /* 偏移下一个<> */
            p_dst_page += 1;

            /* 该位置没有匹配*/
            if((rule->subs_src_page[pos_num].rm_so == -1))
            {
                continue;
            }

            /* 保留替换dest_page前的部分*/
            str_length = rule->subs_src_page[pos_num].rm_so - offset;
            memcpy(p_url_repled, req_url+offset, str_length);
            p_url_repled += str_length;

            /* 将目标内容替换到指定位置 */
            str_length = strlen(p_dst_page_element);
            memcpy(p_url_repled, p_dst_page_element, str_length);
            p_url_repled += str_length;
            
            offset = rule->subs_src_page[pos_num].rm_eo;

        }
        /* 追加替换位置后的部分*/
        *p_url_repled = '\0';
        strcat(url_repled, req_url+offset);
    }
    else
    {
        /* 直接替换*/
        strcpy(url_repled, rule->dest_pages[dest_index]);
    }
    return IPTRAFFIC_FUNC_SUCCESS;
}

inline void build_cookie_repled(unsigned int secondes, char* cookie)
{
    time_t lt;
    struct tm *ptr = NULL;
    lt = time(NULL) + secondes; // 12 Hours

    ptr = gmtime(&lt);
    strftime(cookie, 100, "\r\nSet-Cookie: apxlp=1; expires=%a, %d-%b-%Y %T GMT", ptr);

    return;
}

#if 0
inline void build_custom_cookie(unsigned int secondes, char* cookie,int index)
{
    time_t lt;
    struct tm *ptr = NULL;
    lt = time(NULL) + secondes; // 12 Hours
    int offset = 0;
    
    ptr = gmtime(&lt);
    offset = sprintf(cookie, "\r\nSet-Cookie: apxlp_index=%d; ", index);    
    strftime(cookie+offset, 100, "expires=%a, %d-%b-%Y %T GMT", ptr);

    return;
}
#endif

inline void build_response_payload(struct rule_entry_s *rule, struct http_request_s *req, struct http_response_s* resp)
{
    u_char type = rule->type_repled;
    u_char type_cookie = rule->type_set_cookie;
    u_char* ptr = resp->payload;
    unsigned int    url_repled_len = strlen(resp->url);
    unsigned int    content_len = 0;
    unsigned int    buf_len = 0;
    char            buf[64];
    
    memcpy(ptr, g_resp_element_table[type].header, g_resp_element_table[type].header_len);
    ptr+=g_resp_element_table[type].header_len;


    content_len = g_resp_element_table[type].resp_body_start_len + g_resp_element_table[type].resp_body_middle_len + g_resp_element_table[type].resp_body_end_len;
    
    switch(type)
    {
        case REDIRECT_TYPE_302:
        {
            memcpy(ptr, resp->url, url_repled_len);
            ptr+=url_repled_len;

            break;
        }
        case REDIRECT_TYPE_JS_IFRAME:
        case REDIRECT_TYPE_JS:
        {
            content_len+=url_repled_len;
            break;
        }

        default:
        {
            content_len += url_repled_len;
            break;
        }
    }

    switch (type_cookie)
    {
        case COOKIE_SET:
            build_cookie_repled(rule->cookie_valid, resp->cookie); 
            buf_len = strlen(resp->cookie);
            memcpy(ptr, resp->cookie, buf_len);
            ptr+=buf_len;
            break;
        default:
            break;
    }

    sprintf(buf, "\r\nContent-Length: %d\r\n\r\n", content_len);
    buf_len = strlen(buf);
    memcpy(ptr, buf, buf_len);
    ptr+=buf_len;  
    
    /* 302 响应无body 内容*/
    if (type!=REDIRECT_TYPE_302)
    {
        memcpy(ptr, g_resp_element_table[type].resp_body_start, g_resp_element_table[type].resp_body_start_len);
        ptr+=g_resp_element_table[type].resp_body_start_len;

        if (type==REDIRECT_TYPE_JS)
        {
            memcpy(ptr, req->url, req->url_len);
            ptr+=req->url_len;
        }
        else
        {
            memcpy(ptr, resp->url, url_repled_len);
            ptr+=url_repled_len;
        }

        memcpy(ptr, g_resp_element_table[type].resp_body_middle, g_resp_element_table[type].resp_body_middle_len);
        ptr+=g_resp_element_table[type].resp_body_middle_len;

        if (type==REDIRECT_TYPE_JS_IFRAME)
        {
            /* 此处用源URL 放到框架中返回*/
            //memcpy(ptr, req->url, req->url_len);
            //ptr+=req->url_len;
            memcpy(ptr, g_resp_element_table[type].resp_body_end, g_resp_element_table[type].resp_body_end_len);
            /* 如果url 中已有?, 则小尾巴前缀改为& */
            //if (strchr(req->url, '?') && (*ptr == '?'))
            //{
            //    *ptr = '&';
            //}
        }
        else
        {
            if (type==REDIRECT_TYPE_JS)
            {
                memcpy(ptr, resp->url, url_repled_len);
                ptr+=url_repled_len;
            }
            memcpy(ptr, g_resp_element_table[type].resp_body_end, g_resp_element_table[type].resp_body_end_len);
        }
        ptr+=g_resp_element_table[type].resp_body_end_len;
    }

    *ptr = '\0';

}

struct rule_entry_s * match_rules_repled(struct http_request_s* r, struct list_s * l, struct filter_s* filter, struct http_response_s* resp)
{
    int status = 0;
    struct rule_entry_s *rule = NULL;

    for (;l; l=l->next)
    {
        rule =(struct rule_entry_s *) l->entry;

        /* src_page没命中，继续查找下一条规则 */
        status = regexec(&(rule->reg_src_page), r->url, MAX_REGEX_SUBSLEN, rule->subs_src_page, 0);
        if (REG_NOMATCH == status)
        {
            continue;
        }

        /* agent命中，此条规则相当于没有匹配中，继续查找下一条规则 */
        if (FILTER_NULL != rule->type_filter_agent)
        {
            if (TRUE == detect_filter_useragent(rule->type_filter_agent, &(rule->reg_agent), r))
            {
                continue;
            }
        }

        /* referer命中，此条规则相当于没有匹配中，继续查找下一条规则 */
        if (FILTER_NULL != rule->type_filter_referer)
        {
            if (TRUE == detect_filter_referer(rule->type_filter_referer, &(rule->reg_referer), r))
            {
                continue;
            }
        }

        /* 有cookie标志位，并且含有我们设置的cookie，则该规则不符合，退出 */
        if((rule->type_set_cookie ==  COOKIE_SET) && (detect_cookie_ourselves(r, "apxlp=1")))
        {
            return NULL;
        }
        
        /* 白名单命中，则该规则不符合，退出  */
        if (TRUE == detect_filter_whitelist(rule->type_filter_url, g_cycle.filter, r))
        {
            return NULL;
        }

#ifndef ENABLE_STAT_ONLY
        resp->index = RANDOM_NUM;
        if(resp->index >= rule->percent)
        {
            return NULL;
        }
#endif
        
        return rule;

    }
    
    return NULL;
}

void process_pkt(unsigned char* arg, const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    int rtn = IPTRAFFIC_FUNC_SUCCESS;
    struct iphdr*  ip_hdr = NULL;
    struct tcphdr* tcp_hdr = NULL;
    struct ethhdr * eth_hdr = NULL;
    unsigned char* cp = (unsigned char*)packet;
    struct http_request_s *req = g_cycle.request;
    struct http_response_s *resp = g_cycle.response;
    struct list_s * l = NULL;

    eth_hdr = (struct ethhdr*)cp;
    
    /* only IP or PPP */
    u_int16_t ether_type = ntohs(eth_hdr->h_proto);
    if( ether_type != 0x0800 && ether_type != 0x8100)
    {   
        return;
    }
    cp = cp + ETHER_HDR_LEN;

    /* check 802.1Q packet*/
    if (ether_type == 0x8100)
    {
        cp = cp + 2;
        
        if (cp[0] == 0x88 && cp[1] == 0x64)         /* PPPOE */
        {
            cp = cp + 10;
        }
        else if (cp[0] == 0x08 && cp[1] == 0x00)    /* VLAN */
        {
            cp = cp + 2;
        }
        else
        {
            return;
        }
    }

    ip_hdr = (struct iphdr*)cp;
	cp+=(ip_hdr->ihl*4);
	//UDP报头
	if(ip_hdr->protocol == 0x11)
	{
		cp+=8;
		//GPRS报头
		u_int8_t gtp_flag = *cp;
		switch(gtp_flag)
        {
            case 0x30:
                cp+=8;
                break;            
            case 0x32:
                cp+=12;
                break;  
            default:    
                break;
        }
		//真正的IP报文
		ip_hdr = (struct iphdr*)cp;
		cp+=(ip_hdr->ihl*4);
	}
    
    tcp_hdr = (struct tcphdr*)cp;
    cp+=(tcp_hdr->doff*4);

    if (memcmp(cp, "GET", 3) == 0)
    {
        cp+=4;
    }
    else if(memcmp(cp, "POST", 4) == 0)
    {
        cp+=5;
    }
    else
    {
        /* 非GET/POST请求包 */
        return;
    }

    /* 匹配GET请求各个字段失败 */
    rtn = http_parse_get(req, cp);
    if (IPTRAFFIC_FUNC_ERROR == rtn)
    {
        return;
    }
    
    /* http 报文错误 */
    if ((req->host_len <= 0) || (req->uri_len <= 0))
    {
        return;
    }
   
#if 0
     /* 无效报文，例如:图片、视频、文件等 */
    if(http_detect_request_type(req->url, req->url_len) == IPTRAFFIC_FUNC_ERROR)
    {
        return;
    }
#endif   

    /* 依据host为关键字在hash表中搜寻规则 */            
    hashmap_entry_by_key(g_cycle.hashmap, req->host, (void **)&l);
    if (NULL == l)
    {
        /* 根据host关键字未找到相应的规则，在默认规则中第二次查找 */
        hashmap_entry_by_key(g_cycle.hashmap, "null", (void **)&l);
        if (NULL == l)
        {
            return;
        }
    }

    /* 匹配该规则 */
    struct rule_entry_s *rule = match_rules_repled(req, l, g_cycle.filter, resp);    
    if (!rule)
    {
        return;
    }

#ifndef ENABLE_STAT_ONLY
    /* 生成替换后的链接*/
    rtn = build_url_repled(resp->index, rule, req->url, resp->url);
    if(IPTRAFFIC_FUNC_ERROR == rtn)
    {
        warnlog("Wrong rule!Please check it:url=%s",req->url);
        return;
    }
                                
    build_response_payload(rule, req, resp);
                             
    /* 回响应报文*/
    rtn = send_http_get_ack(eth_hdr, ip_hdr, tcp_hdr);
    if (rtn != IPTRAFFIC_FUNC_SUCCESS)
    {
        errlog( "Failed to send http get ack");
        return;
    }
                                
    /* 发送响应报文*/
    rtn = send_http_resp_repled(eth_hdr, ip_hdr, tcp_hdr, resp->payload);      
    if (rtn != IPTRAFFIC_FUNC_SUCCESS)
    {
        errlog( "Failed to send response with replaced URI");
        return;
    }
#endif

    rule->matched_count++;

    return;
}



