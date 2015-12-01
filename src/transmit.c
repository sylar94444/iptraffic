#include "transmit.h"
#include "log.h"
#include "util.h"

/* 回报设备句柄 */
static libnet_t* libnet_handle;   /* GLOBAL */
/* 指定回报的mac地址 */
static unsigned char dest_mac[ETH_ALEN]={0x00,0x00,0x5E,0x00,0x01,0xE7};    /* GLOBAL */

int init_libnet(const char *dev, const char *dmac)
{
    char err_buf[LIBNET_ERRBUF_SIZE];

    memset(err_buf, 0, LIBNET_ERRBUF_SIZE);
    
    /* 获取设备句柄 */    
#ifdef ENABLE_LIBNET_LINK
    libnet_handle = libnet_init(LIBNET_LINK, dev, err_buf);
#else
    libnet_handle = libnet_init(LIBNET_RAW4, dev, err_buf);
#endif
    
    if(libnet_handle == NULL) 
    {
        errlog("Couldn't open device %s:%s", dev, err_buf);
        return IPTRAFFIC_FUNC_ERROR;
    }

    /* 指定回报报文MAC */
    if(dmac && (strlen(dmac) > 0))
    {
        char buf[ETH_ALEN];
        memset(buf, 0, ETH_ALEN);
        
        mac_str_to_bin( dmac, buf);
        memcpy(dest_mac, buf, ETH_ALEN);
    }

#ifdef ENABLE_DEBUG
    dbglog("MAC:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x", dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
#endif

    return IPTRAFFIC_FUNC_SUCCESS;
}

void close_libnet(void)
{
    if(libnet_handle)
        libnet_destroy(libnet_handle);
    libnet_handle = NULL;
}

int send_http_get_ack(struct ethhdr* eth_hdr, struct iphdr* ip_hdr, struct tcphdr* tcp_hdr)
{
    libnet_ptag_t rtn = 0;

    rtn = libnet_build_tcp (ntohs(tcp_hdr->dest),   /* src port */
                            ntohs(tcp_hdr->source),   /* destination port */
                            ntohl(tcp_hdr->ack_seq),     /* sequence number */
                            ntohl(tcp_hdr->seq)+ntohs(ip_hdr->tot_len)-ip_hdr->ihl*4-tcp_hdr->doff*4,    /* acknowledgement */
                            TH_ACK, /* control flags */
                            ntohs(tcp_hdr->window),    /* window */
                            0,    /* checksum - 0 = autofill */
                            0,    /* urgent */
                            LIBNET_TCP_H,     /* header length */
                            NULL,     /* payload */
                            0,    /* payload length */
                            libnet_handle,    /* libnet context */
                            0);   /* protocol tag */
    if (-1 == rtn)
    {
        errlog("%s", libnet_geterror(libnet_handle));
        return IPTRAFFIC_FUNC_ERROR;
    }
    
    rtn = libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H,    /* length */
                              0,    /* TOS */
                              libnet_get_prand (LIBNET_PRu16),    /* IP ID */
                              0,    /* frag offset */
                              80,    /* TTL:80 #127 */
                              IPPROTO_TCP,    /* upper layer protocol */
                              0,    /* checksum, 0=autofill */
                              ip_hdr->daddr,    /* src IP */
                              ip_hdr->saddr,    /* dest IP */
                              NULL,    /* payload */
                              0,    /* payload len */
                              libnet_handle,    /* libnet context */
                              0);    /* protocol tag */
    if (-1 == rtn)
    {
        errlog("%s", libnet_geterror(libnet_handle));
        return IPTRAFFIC_FUNC_ERROR;
    }

#ifdef ENABLE_LIBNET_LINK
    rtn = libnet_build_ethernet(
#ifdef ENABLE_MAC_SPECIFIED
                    dest_mac,                                   /* ethernet destination */
#else
                    eth_hdr->h_source,                                   /* ethernet destination */
#endif
                    eth_hdr->h_dest,                                   /* ethernet source */
                    ETHERTYPE_IP,                               /* protocol type */
                    NULL,                                       /* payload */
                    0,                                          /* payload size */
                    libnet_handle,                                          /* libnet handle */
                    0);                                         /* libnet id */
    if (-1 == rtn)
    {
        errlog("%s", libnet_geterror(libnet_handle));
        return IPTRAFFIC_FUNC_ERROR;
    }
#endif

    rtn = libnet_write(libnet_handle);
    if (rtn == -1) {
        errlog( "Failed to libnet_write: %s", libnet_geterror(libnet_handle));
        libnet_clear_packet(libnet_handle);
        return IPTRAFFIC_FUNC_ERROR;
    }

    libnet_clear_packet(libnet_handle);

    return IPTRAFFIC_FUNC_SUCCESS;
}

int send_http_resp_repled(struct ethhdr* eth_hdr, struct iphdr* ip_hdr, struct tcphdr* tcp_hdr,unsigned char* payload)
{
    libnet_ptag_t  rtn  = 0;
    unsigned int   payload_len = strlen((char *)payload);
    unsigned int   str_len =0;
    unsigned int   i =0;

    while (i < payload_len)
    {
        str_len = payload_len - i;
        if (str_len > MAX_TCP_FRAGMENT_LEN)
        {
            str_len = MAX_TCP_FRAGMENT_LEN;
        }
        
        rtn = libnet_build_tcp (ntohs(tcp_hdr->dest),    /* src port */
                                ntohs(tcp_hdr->source),      /* destination port */
                                ntohl(tcp_hdr->ack_seq) + i,     /* sequence number */
                                ntohl(tcp_hdr->seq)+ntohs(ip_hdr->tot_len)-ip_hdr->ihl*4-tcp_hdr->doff*4,    /* acknowledgement */
                                TH_ACK|TH_PUSH,    /* control flags */
                                ntohs(tcp_hdr->window),    /* window */
                                0,    /* checksum - 0 = autofill */
                                0,    /* urgent */
                                LIBNET_TCP_H + payload_len,      /* total length of the TCP packet */
                                payload + i,      /* payload */
                                str_len,    /* payload length */
                                libnet_handle,    /* libnet context */
                                0);      /* protocol tag */
        if (-1 == rtn)
        {
            errlog("%s", libnet_geterror(libnet_handle));
            return IPTRAFFIC_FUNC_ERROR;
        }
        
        rtn = libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H + str_len,    /* length */
                                  0,    /* TOS */
                                  libnet_get_prand (LIBNET_PRu16),    /* IP ID */
                                  0x4000,    /* frag offset */
                                  80,    /* TTL:80 */
                                  IPPROTO_TCP,    /* upper layer protocol */
                                  0,    /* checksum, 0=autofill */
                                  ip_hdr->daddr,    /* src IP */
                                  ip_hdr->saddr,    /* dest IP */
                                  NULL,    /* payload */
                                  0,    /* payload len */
                                  libnet_handle,    /* libnet context */
                                  0);    /* protocol tag */
        if (-1 == rtn)
        {
            errlog("%s", libnet_geterror(libnet_handle));
            return IPTRAFFIC_FUNC_ERROR;
        }
        
#ifdef ENABLE_LIBNET_LINK
        rtn = libnet_build_ethernet(
#ifdef ENABLE_MAC_SPECIFIED
                    dest_mac,                                     /* ethernet destination */
#else
                    eth_hdr->h_source,                                     /* ethernet destination */
#endif
                    eth_hdr->h_dest,                                   /* ethernet source */
                    ETHERTYPE_IP,                               /* protocol type */
                    NULL,                                       /* payload */
                    0,                                          /* payload size */
                    libnet_handle,                                          /* libnet handle */
                    0);                                         /* libnet id */
        if (-1 == rtn)
        {
            errlog("%s", libnet_geterror(libnet_handle));
            return IPTRAFFIC_FUNC_ERROR;
        }
#endif

        if (-1 == libnet_write(libnet_handle))
        {
            errlog( "Failed to libnet_write: %s", libnet_geterror(libnet_handle));
            libnet_clear_packet(libnet_handle);
            return IPTRAFFIC_FUNC_ERROR;
        }
        
        libnet_clear_packet(libnet_handle);
        
        i = i + MAX_TCP_FRAGMENT_LEN;
    }
    
    return IPTRAFFIC_FUNC_SUCCESS;
}

