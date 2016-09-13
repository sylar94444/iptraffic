#ifndef __IPTRAFFIC_H__
#define __IPTRAFFIC_H__

#include "sysdef.h"
#include "process.h"
#include "hash.h"
#include "list.h"

#define IPTRAFFIC_VERSION    "1.6.8"    

/* libcapĬ��BPF���˹��� */
#define DEFAULT_BPF_EXPRESSION  "greater 60 and tcp dst port 80 and tcp[20:4]==0x47455420"    

#define MAX_BUCKETS 65536         /* HASH������ӳ����� */
#define MAX_REGEX_SUBSLEN 100    /* ������ʽƥ��ı�� */

/* �����ƥ����� */
typedef struct rule_entry_s {
	/* ��־���� */
	int log_flag;
	
    /* �������ļ���ȡ��typeֵ */
    unsigned int type;

    /* referer������ʽ�ַ��� */
    char *referer;

    /* agent������ʽ�ַ��� */
    char *agent;
    
    /* src_page������ʽ�ַ��� */
    char* src_page;

    /* �������ļ���ȡ��dest_page�ַ��� */    
    char** dest_pages;
    
    /* ���е�dest_page����֮�� */
    int percent;

    /* src_page���������� */
    regex_t reg_src_page;
    regmatch_t subs_src_page[MAX_REGEX_SUBSLEN];

    /* referer������������ʽ */
    regex_t reg_referer;
    /* agent������������ʽ */
    regex_t reg_agent;

    /* type�ֽ����� */
    u_char type_repled;            /* src_page �滻���� */
    u_char type_repled_pos;        /* src_page �滻λ�� */
    u_char type_filter_agent;    /* ����agent���еİ����� */
    u_char type_filter_referer; /* ����referer���еİ����� */
    u_char type_set_cookie;  /* cookie�������� */
    u_char type_filter_url;        /* ����url���еİ����� */

    /* cookie��Ч�� */
    unsigned int cookie_valid;
    
    /* ���������еĴ��� */
    unsigned long matched_count;
}rule_entry_t;

/* ���������˹��� */
struct filter_s{
    /* referer������������ʽ */
    regex_t white_referer;
    /* url������������ʽ */
    regex_t white_url;
};

/* ���ṹ */
struct cycle_s {
    /* ������豸���� */
    char *recv_device;
    
    /* iptraffic.conf ����·�����ļ��� */
    char *iptraffic_filename;

    /* �ر����豸���� */
    char *send_device;

    /* ָ���ر���mac��ַ */
    char *dest_mac;

    /* pid_list ����·�����ļ��� */
    char *pidlist_filename;
    
    /* white_list ����·�����ļ��� */
    char *whitelist_filename;

    /* bpf ���˹��� */    
    char *bpf;

    /* pid_list�������� */
    struct list_s *rule_list;

    /* �����ĵĻ����� */
    struct http_request_s *request;

    /* �ر��Ļ����� */
    struct http_response_s *response;

    /* ���˵İ��������򣬰���url\agent\referer */
    struct filter_s *filter;

    /* ����ƥ���hash�� */
    hashmap_t hashmap;

	/* �������ݵ�socet fd */	    
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
