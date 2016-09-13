#ifndef __IPTRAFFIC_H__
#define __IPTRAFFIC_H__

#include "sysdef.h"
#include "process.h"
#include "hash.h"
#include "list.h"

#define IPTRAFFIC_VERSION    "1.6.8"    

/* libcap默认BPF过滤规则 */
#define DEFAULT_BPF_EXPRESSION  "greater 60 and tcp dst port 80 and tcp[20:4]==0x47455420"    

#define MAX_BUCKETS 65536         /* HASH表的最大映射个数 */
#define MAX_REGEX_SUBSLEN 100    /* 正则表达式匹配的标记 */

/* 请求包匹配规则 */
typedef struct rule_entry_s {
	/* 日志开关 */
	int log_flag;
	
    /* 从配置文件读取的type值 */
    unsigned int type;

    /* referer正则表达式字符串 */
    char *referer;

    /* agent正则表达式字符串 */
    char *agent;
    
    /* src_page正则表达式字符串 */
    char* src_page;

    /* 从配置文件读取的dest_page字符串 */    
    char** dest_pages;
    
    /* 所有的dest_page概率之和 */
    int percent;

    /* src_page的正则表达结果 */
    regex_t reg_src_page;
    regmatch_t subs_src_page[MAX_REGEX_SUBSLEN];

    /* referer白名单正则表达式 */
    regex_t reg_referer;
    /* agent白名单正则表达式 */
    regex_t reg_agent;

    /* type分解类型 */
    u_char type_repled;            /* src_page 替换类型 */
    u_char type_repled_pos;        /* src_page 替换位置 */
    u_char type_filter_agent;    /* 根据agent放行的白名单 */
    u_char type_filter_referer; /* 根据referer放行的白名单 */
    u_char type_set_cookie;  /* cookie处理类型 */
    u_char type_filter_url;        /* 根据url放行的白名单 */

    /* cookie有效期 */
    unsigned int cookie_valid;
    
    /* 本规则命中的次数 */
    unsigned long matched_count;
}rule_entry_t;

/* 白名单过滤规则 */
struct filter_s{
    /* referer白名单正则表达式 */
    regex_t white_referer;
    /* url白名单正则表达式 */
    regex_t white_url;
};

/* 主结构 */
struct cycle_s {
    /* 镜像口设备名称 */
    char *recv_device;
    
    /* iptraffic.conf 包含路径的文件名 */
    char *iptraffic_filename;

    /* 回报口设备名称 */
    char *send_device;

    /* 指定回报的mac地址 */
    char *dest_mac;

    /* pid_list 包含路径的文件名 */
    char *pidlist_filename;
    
    /* white_list 包含路径的文件名 */
    char *whitelist_filename;

    /* bpf 过滤规则 */    
    char *bpf;

    /* pid_list规则链表 */
    struct list_s *rule_list;

    /* 请求报文的缓冲区 */
    struct http_request_s *request;

    /* 回报的缓冲区 */
    struct http_response_s *response;

    /* 过滤的白名单规则，包括url\agent\referer */
    struct filter_s *filter;

    /* 快速匹配的hash表 */
    hashmap_t hashmap;

	/* 发送数据的socet fd */	    
    int szport;
    char* szhost;
	int sock_fd;

};

void usage(char *prog);

void killer(int sig);

void SignHandler1(int iSignNo);

void SignHandler2(int iSignNo);

void init_cycle(struct cycle_s *c);

void read_config_file(struct cycle_s *c, const char *path);

void print_config_file(void);

void print_matched_stat(void);

void uninit_cycle();

#endif
