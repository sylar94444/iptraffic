#include "iptraffic.h"
#include "log.h"
#include "util.h"
#include "capture.h"
#include "transmit.h"

/* 主结构 */
struct cycle_s g_cycle;        /* GLOBAL */

/******************************************************************************
* Function   :usage
* Description:
* Output     :
* Input      :用户输入的参数
* Return     :
* Note       :
******************************************************************************/
void usage(char *prog)
{
    fprintf(stderr, "Version:%s \nUsage: %s -i [RECV NIC] -c [CONFIG FILE] -l [LOG FILE]\n", IPTRAFFIC_VERSION, prog);
    exit(-1);
}

/******************************************************************************
* Function   :killer
* Description:处理一系列进程退出信号
* Output     :
* Input      :foo,信号值
* Return     :
* Note       :
******************************************************************************/
void killer(int sig)
{
    runlog("Received signal %d, program exiting...", sig);
    close_log();
    uninit_cycle(&g_cycle);
    close_pcap();
    close_libnet();
    exit(1);
}

/* DUMP所有的配置信息 */
void SignHandler1(int iSignNo)
{
    print_config_file();
}

/* 统计命中的规则数 */
void SignHandler2(int iSignNo)
{
    print_matched_stat();
}

static void reg_compile(regex_t *reg, const char *str, bool enable_sub)
{
    int flag;

    if(str == NULL)
        return;

    if(enable_sub)
        flag = (REG_EXTENDED | REG_ICASE);
    else
        flag = (REG_EXTENDED | REG_ICASE | REG_NOSUB);
    
    if (0 != regcomp(reg, str, flag)) 
    {
        errlog("Failed to regcomp %s regex pattern.\n", str);
        exit(5);
    }
}

static void add_src_page(struct cycle_s *c, char *line)
{
    struct list_s *node = NULL;
    struct rule_entry_s *rule = NULL;
    unsigned int type = -1;
    char host[MAX_BUFFER_LEN] = {0};
    char referer[MAX_BUFFER_LEN] = {0};
    char agent[MAX_BUFFER_LEN] = {0};
    char src_page[MAX_BUFFER_LEN] = {0};
    unsigned int cookie_valid = 0;
	int log_flag = 1;
    
    if(line == NULL)
        return;
    
//    sscanf(line, "type=%x host=%s referer=%s src_page=%s", &type, host, referer, src_page);
    char *p = NULL;
    int ret = 0;
    p = strtok(line," ");
    while(p != NULL)
    {
        if(STREQ(p, "type="))
        {
            ret = sscanf(p, "type=%x", &type);
            if(ret == -1)
            {
                warnlog("type does not set:%s", line);
            }
        }
        else if(STREQ(p, "host="))
        {
            ret = sscanf(p, "host=%s", host);
            if(ret == -1)
             {
                 warnlog("host does not set:%s", line);
             }
        }          
        else if(STREQ(p, "referer="))
        {
            ret = sscanf(p, "referer=%s", referer);
            if(ret == -1)
            {
                warnlog("referer does not set:%s", line);
            }
        }
        else if(STREQ(p, "agent="))
        {
            ret = sscanf(p, "agent=%s", agent);
            if(ret == -1)
            {
                warnlog("agent does not set:%s", line);
            }
        }
        else if(STREQ(p, "cookie_valid="))
        {
            ret = sscanf(p, "cookie_valid=%u", &cookie_valid);
            if(ret == -1)
            {
                warnlog("cookie_valid does not set:%s", line);
            }
        }
        else if(STREQ(p, "src_page="))
        {
            ret = sscanf(p, "src_page=%s", src_page);
            if(ret == -1)
            {
                warnlog("src_page does not set:%s", line);
            }
        }
        else if(STREQ(p, "log="))
        {
            ret = sscanf(p, "log=%d", &log_flag);
            if(ret == -1)
            {
                warnlog("log_flag does not set:%s", line);
            }
        }		
        else
        {
            ;
        }
        p = strtok(NULL," ");
    }

    rule = (struct rule_entry_s *)MALLOC(rule_entry_t, 1);
    rule->dest_pages = (char**)MALLOC(char*, 100);
    rule->type = type;
	rule->log_flag = log_flag;
    rule->type_repled = type&0xF;
    rule->type_set_cookie = (type>>4)&0xF;
    rule->type_repled_pos = (type>>8)&0xF;
    rule->type_filter_url = (type>>12)&0xF;
    rule->type_filter_agent = (type>>16)&0xF;
    rule->type_filter_referer = (type>>20)&0xF;
    rule->referer = strdup(referer);
    reg_compile(&(rule->reg_referer), referer, false);
    rule->agent= strdup(agent);
    reg_compile(&(rule->reg_agent), agent, false);
    rule->cookie_valid = (cookie_valid>0)?cookie_valid:43200; //默认值12小时
    rule->src_page = strdup(src_page);
    reg_compile(&(rule->reg_src_page), src_page, true);
    rule->percent = 0;

    node = init_list();    
    node->index = strdup(host);
    node->entry = rule;

    if(c->rule_list == NULL)
        c->rule_list = node;
    else
        insert_tail_list(c->rule_list, node);
}

static void free_rules(struct list_s *l)
{
    struct list_s *p = l;
    while(p)
    {
        struct rule_entry_s *rule = (struct rule_entry_s *)p->entry;

        regfree(&rule->reg_referer);
        regfree(&rule->reg_agent);
        regfree(&rule->reg_src_page);
        FREE(rule->dest_pages);
        FREE(rule);

        p = p->next;
    }
}

/*
 * 将dst_page插入链表最后一个节点
 */
void add_dst_page(struct cycle_s *c, const char *line)
{
    pNode p = NULL;
    struct rule_entry_s *rule = NULL;
    char buf[MAX_BUFFER_LEN] = {0};
    unsigned int percent = 0;
    unsigned int i = 0;
    char *q = NULL;
    
    if(line == NULL)
        return;

//    sscanf(line, "dest_page=%s percent=%d", dst_page, &percent);
    q = strstr(line, "percent=");
    if(!q)
    {
        errlog("Wrong rule:%s",line);
        return;
    }
    
    memcpy(buf, line+strlen("dest_page="), strlen(line)-strlen(q)-strlen("dest_page="));
    sscanf(q, "percent=%d", &percent);
    q = ignore_space(buf);

    p = get_tail_list(c->rule_list);
    if(p == NULL)
    {
        errlog("Can't find any rules.");
        return;
    }

    rule = (struct rule_entry_s *)p->entry;
    
    for (i = 0; i<percent; i++)
    {
        if((rule->percent)>100)
        {
            errlog("%s percent more than 100%.\n", rule->src_page);
            exit(-1);
        }
        
        rule->dest_pages[rule->percent] = strdup(q);
        (rule->percent)++;
    }
}

/******************************************************************************
* Function   : read_white_list
* Description: 读取url白名单,包括white_list.conf
* Output     : struct cycle_s *c
* Input      : path
* Return     : 
* Note       :
******************************************************************************/
static void read_white_list(struct cycle_s *c, const char *path)
{
    FILE *fp = NULL;
    char line[256] = {0};
    char buf[10240] = {0};
    int flag = 0;

    fp = open_file(path, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Open whitelist file %s failed!\n", path);
        return;
    }
    
    while (fgets(line, sizeof (line), fp))
    {
        char *cp = ignore_space(line);

        /* 忽略空白行和以#号开头的行 */
        char in = *cp;
        if((strlen(cp) <= 0)||(in == ';' || in == '#'))
            continue;

        sscanf(cp, "%s\n", line);
        if(flag == 0)
        {
            flag = 1;
        }
        else
        {
            strcat(buf,"|");
        }
        strcat(buf,line);
    }

#ifdef ENABLE_DEBUG
    dbglog("white_list:%s", buf);
#endif

    reg_compile(&(c->filter->white_url), buf, false);
    
    close_file(fp);
}

static void
parse_line (struct cycle_s *c, char *line)
{
    char *p = line;
    char in;
    char buf[MAX_BUFFER_LEN] = {0};

    do
    {
        in = *p;

        if (SPACE (in))
            continue;

        if (in == ';' || in == '#') /* comment */
        {
            break;
        }
        if(STREQ(p, "send_device="))
        {
            sscanf(p, "send_device=%s\n", buf);
            c->send_device = strdup(buf);
            if(strlen(buf) <= 0)
            {
                warnlog("Send_device does not set!");
            }
            break;
        }
        else if(STREQ(p, "dest_mac="))
        {
            sscanf(p, "dest_mac=%s\n", buf);         
            c->dest_mac = strdup(buf);
            if(strlen(buf) <= 0)
            {
                warnlog("Dest_mac does not set, will be using default MAC!");
            }
            break;
        }
        else if(STREQ(p, "pid_list="))
        {
            sscanf(p, "pid_list=%s\n", buf);
            if(strlen(c->pidlist_filename) + strlen(buf) > MAX_BUFFER_LEN-2)
            {
                warnlog("pidlist file name is too long!");
            }
            else
            {
                if(strlen(c->pidlist_filename)!=0)
                {
                    strcat(c->pidlist_filename, ";");
                }
                strcat(c->pidlist_filename, buf);
            }   
            if(strlen(buf)>0)
            {
                read_config_file(c, buf);           
            }
            else
            {
                warnlog("Pid_list does not set!");
            }
            break;

        }
        else if(STREQ(p, "white_list="))
        {
            sscanf(p, "white_list=%s\n", buf);
            c->whitelist_filename = strdup(buf);
            if(strlen(buf)>0)
            {
                read_white_list(c, c->whitelist_filename);        
            }
            else
            {
                warnlog("White_list does not set!");
            }   
            break;
        }
        else if(STREQ(p, "referer="))
        {
            sscanf(p, "referer=%s\n", buf);
            if(strlen(buf) <= 0)
            {
                warnlog("Referer does not set!");
            }
            reg_compile(&(c->filter->white_referer), buf, false);
            break;
        }
        else if(STREQ(p, "bpf="))
        {
            sscanf(p, "bpf=%[^\n]\n", buf);
            if(strlen(buf) <= 0)
            {
                warnlog("Bpf does not set!");
            }
            c->bpf = strdup(buf);
            break;
        }
        else if(STREQ(p, "type="))
        {
            add_src_page(c, p);
            break;
        }
#ifndef ENABLE_STAT_ONLY
        else if(STREQ(p, "dest_page="))
        {
            add_dst_page(c, p);
            break;
        }
#endif
        else if(STREQ(p, "szhost="))
        {
            sscanf(p, "szhost=%s\n", buf);         
            c->szhost = strdup(buf);
            if(strlen(buf) <= 0)
            {
                warnlog("Send server host does not set, will be using default ip!");
            }
            break;
        }
        else if(STREQ(p, "szport="))
        {
        	short port = 0;
            sscanf(p, "szport=%d", &port); 
			c->szport = port;
            break;
        }		
        else
        {
            break;
        }
    } while (*p++ != '\0');
}

/******************************************************************************
* Function   : read_config_file
* Description: 读取配置文件,包括iptraffic.conf和pid_list.conf
* Output     : struct cycle_s *c
* Input      : path
* Return     : 
* Note       :
******************************************************************************/
void read_config_file(struct cycle_s *c, const char *path)
{
    FILE *fp = NULL;
    char line[MAX_BUFFER_LEN] = {0};

    fp = open_file(path, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Open config file %s failed!\n", path);
        return;
    }
    
    while (fgets(line, sizeof(line), fp))
    {
        parse_line (c, line);
    }
    
    close_file(fp);
}

/******************************************************************************
* Function   : init_cycle
* Description: 初始化struct cycle_s变量
* Output     :
* Input      : c
* Return     : 
* Note       :
******************************************************************************/
void init_cycle(struct cycle_s *c)
{
    c->recv_device = NULL;
    c->iptraffic_filename = NULL;
    c->send_device = NULL;
    c->dest_mac = NULL;
    c->pidlist_filename = (char *)MALLOC(char, MAX_BUFFER_LEN);
    c->whitelist_filename = NULL;
    c->bpf = DEFAULT_BPF_EXPRESSION;
    
    /* pid_list链表初始化 */
    c->rule_list = NULL;

    /* 初始化白名单列表 */
    c->filter = (struct filter_s *)MALLOC(struct filter_s,1);

    /* 请求报文的缓冲区 */
    c->request = http_new_request();

    /* 回报的缓冲区 */
    c->response = http_new_response();

    /* 快速匹配的hash表 */
    c->hashmap = hashmap_create(MAX_BUCKETS);

	/* init buffer */
    c->length = 0;
	c->buffer = (char*)MALLOC(char, MAX_PACKET_LEN);
    
    /* init dcenter socket */
	c->szhost = (char *)MALLOC(char, 32);
    c->sock_fd = 0;  	
}

void uninit_cycle(struct cycle_s *c)
{
    if(!c)
        return;

    free_buf(c->pidlist_filename);

      if(c->rule_list)
      {
          free_rules(c->rule_list);
          clear_list(c->rule_list);
      }

    if(c->new_rule_list)
        clear_list(c->new_rule_list);

    if(c->request)
        http_free_request(c->request);

    if(c->response)
        http_free_response(c->response);

    if(c->filter)
    {
        regfree(&c->filter->white_referer);
        regfree(&c->filter->white_url);
        FREE(c->filter);
    }

    if(c->hashmap)
        hashmap_delete(c->hashmap);
}

void show_settings(void)
{    
    runlog( "Process start......");
    runlog("---------------------------------------------------");
    runlog("recv_device=%s",g_cycle.recv_device);
    runlog("send_device=%s",g_cycle.send_device);
    runlog("dest_mac=%s",g_cycle.dest_mac);
    runlog("iptraffic_filename=%s",g_cycle.iptraffic_filename);
    runlog("pidlist_filename=%s",g_cycle.pidlist_filename);
    runlog("whitelist_filename=%s",g_cycle.whitelist_filename);
    runlog("bpf=%s",g_cycle.bpf);
    runlog("---------------------------------------------------");
}

/******************************************************************************
* Function   : print_config_file
* Description: 显示配置文件
* Output     : 屏幕打印所有规则
* Input      : struct cycle_s *c
* Return     : 
* Note       :
******************************************************************************/
void print_config_file(void)
{    
    runlog("Print all the options :");
    runlog("---------------------------------------------------");
    struct list_s *p = g_cycle.rule_list;
    int i,j;
    
    while(p)
    {
        struct rule_entry_s *rule = (struct rule_entry_s *)p->entry;
        runlog("type=%x host=%s referer=%s agent=%s cookie_valid=%d src_page=%s", rule->type, p->index, rule->referer, rule->agent, rule->cookie_valid, rule->src_page);
        j=0;
        
        for (i = rule->percent-1; i >= 0; i--)
        {
            j++;
            if ((i == 0) || (0 != strcmp(rule->dest_pages[i] , rule->dest_pages[i-1])))
            {
                runlog("dest_page=%s percent=%d", rule->dest_pages[i], j);
                j = 0;
            }
        }
        p = p->next;
    }
    runlog("---------------------------------------------------");
}

void print_matched_stat(void)
{
    unsigned int i = 0;
    struct list_s *p = g_cycle.rule_list;
    
    runlog("---------------------------------------------------");
    while(p)
    {
        struct rule_entry_s *rule = (struct rule_entry_s *)p->entry;

		if(rule->log_flag==1)
		{
			runlog("The No. %d matched num is: %lu. src_page=%s", i, rule->matched_count, rule->src_page);
        	rule->matched_count = 0;
            i++;
		}
        p = p->next;
    }
    runlog("---------------------------------------------------");
}

void load_hashmap()
{
    struct list_s *list = g_cycle.rule_list;
    struct list_s *new_list = g_cycle.new_rule_list;
    hashmap_t hash = g_cycle.hashmap;
    
    /* host拆分为单个域名，重新建立新的链表 */
    new_list = rebuild_list_by_index(list);

    /* 没有任何策略 */
    if(!new_list)
        return;
    
    /* 以host为索引进行排序 */
    sort_list_by_index(new_list);
    
    struct list_s *p =  new_list;
    struct list_s *s = NULL;
    struct list_s *head = new_list;
    int len = 0;

    //以host为关键字拆分链表，并送入hash表
    while(p)
    {
        s = p;
        p = p->next;
        len++;
        if(!p||strcmp(s->index, p->index))
        {
            s->next = NULL;
            hashmap_insert(hash, s->index, head, len*sizeof(Node));
            
            head = p;
            len = 0;
        }
    }
}

void dcenter_sock_udp_init(void)
{
	g_cycle.sock_fd= socket(AF_INET, SOCK_DGRAM, 0);
}

int main(int argc, char* argv[])
{
    int opt;
    char *logfile = NULL;
    char *configfile = NULL;
    char *recv_dev = NULL;
    
    while((opt = getopt(argc, argv, "i:c:l:h")) != -1)
    {
        switch(opt)
        {
            case 'i':
                recv_dev = strdup(optarg);
                break;            
            case 'c':
                configfile = strdup(optarg);
                break;
            case 'l':
                logfile = strdup(optarg);
                break;     
            default:    /* '?' */
                usage(argv[0]);
                break;
        }
    }

    if (recv_dev == NULL || configfile == NULL)
    {
        usage(argv[0]);
    }
    
    /* STEP1:打开日志文件，获取文件描述符 */
    open_log(logfile);

    /* STEP2:初始化主结构 */
    init_cycle(&g_cycle);
    g_cycle.iptraffic_filename = strdup(configfile);
    g_cycle.recv_device = strdup(recv_dev);

    /* STEP3: 读取配置文件->主结构 */
    read_config_file(&g_cycle, configfile);
	
#ifdef ENABLE_DEBUG
    print_config_file();
#endif

    /* STEP4: 根据规则链表建立hash表 */
    load_hashmap();
    
    /* STEP5:初始化回报缓冲区 */
    init_resp_table();

    /* STEP6: 初始化入口设备句柄 */
    init_pcap(g_cycle.recv_device, g_cycle.bpf);

    /* STEP7: 初始化出口设备句柄 */
    init_libnet(g_cycle.send_device, g_cycle.dest_mac);

    /* STEP8: 处理退出信号 */
    signal(SIGINT, killer);
    signal(SIGQUIT, killer);
    signal(SIGTERM, killer);
    signal(SIGKILL, killer);
    signal(SIGUSR1, SignHandler1);
    signal(SIGUSR2, SignHandler2);

	/* STEP9: 初始化收集数据socket */
	dcenter_sock_udp_init();

    nice(-20);
    
    /* 初始化随机数种子*/
    srand(time(NULL));

    show_settings();

    /* STEP9: 主循环 */
    capture_pcap();

    close_log();
    uninit_cycle(&g_cycle);
    close_pcap();
    close_libnet();
    return 0;
}


