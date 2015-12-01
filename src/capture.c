#include "capture.h"
#include "process.h"
#include "log.h"

/* �ذ��豸��� */
static pcap_t* pcap_handle;            /* GLOBAL */

void init_pcap(const char *dev, const char *bpf)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program  bp;
    
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    /* ��ȡpcap�豸��� */
    pcap_handle = pcap_open_live(dev, 5000, 1, 512, errbuf);
    if( pcap_handle == NULL)
    {
        errlog("Couldn't open device %s:%s", dev, errbuf);
        exit(-1);
    }
    
    /* ���ù��˹��� */
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
* Description: ������ڽذ�����
* Output     : g_pcap_handle����ʼ���õ�libpcapץ��������ָ��
* Input      : interface-��������豸���ƣ�bpf-���˹���
* Return     : APXLP_E_NONE,����ִ�гɹ�;����,����ִ��ʧ��
* Note       :
******************************************************************************/
void capture_pcap(void)
{
    /* ���񲢴������ݰ� */
    if(pcap_loop(pcap_handle, -1, process_pkt, NULL) == -1)
    {
        errlog("Pcap loop error:%s",pcap_geterr(pcap_handle));
        exit(-1);
    }
}

