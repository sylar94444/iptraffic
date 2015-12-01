#include "capture.h"
#include "process.h"
#include "log.h"

/* 截包设备句柄 */
static pcap_t* pcap_handle;            /* GLOBAL */

void init_pcap(const char *dev, const char *bpf)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program  bp;
    
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    /* 获取pcap设备句柄 */
    pcap_handle = pcap_open_live(dev, 5000, 1, 512, errbuf);
    if( pcap_handle == NULL)
    {
        errlog("Couldn't open device %s:%s", dev, errbuf);
        exit(-1);
    }
    
    /* 设置过滤规则 */
    if(pcap_compile(pcap_handle, &bp, bpf, 1, 0) == -1)
    {
        errlog("Couldn't parse filter %s:%s", bpf, pcap_geterr(pcap_handle));
        exit(-1);
    }
    if(pcap_setfilter(pcap_handle, &bp) == -1)
    {
        errlog("Couldn't install filter %s:%s", bpf, pcap_geterr(pcap_handle));
        exit(-1);
    }
}

void close_pcap(void)
{
    if(pcap_handle)
        pcap_close(pcap_handle);
    pcap_handle = NULL;
}

/******************************************************************************
* Function   : capture
* Description: 流量入口截包处理
* Output     : g_pcap_handle，初始化好的libpcap抓包描述符指针
* Input      : interface-流量入口设备名称，bpf-过滤规则
* Return     : APXLP_E_NONE,函数执行成功;其他,函数执行失败
* Note       :
******************************************************************************/
void capture_pcap(void)
{
    /* 捕获并处理数据包 */
    if(pcap_loop(pcap_handle, -1, process_pkt, NULL) == -1)
    {
        errlog("Pcap loop error:%s",pcap_geterr(pcap_handle));
        exit(-1);
    }
}

