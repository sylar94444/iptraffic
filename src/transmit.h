#ifndef __TRANSMIT_H__
#define __TRANSMIT_H__

#include "sysdef.h"

#define MAX_TCP_FRAGMENT_LEN 1400

int init_libnet(const char *dev, const char *dmac);

void close_libnet(void);

int send_http_get_ack(struct ethhdr* eth_hdr, struct iphdr* ip_hdr, struct tcphdr* tcp_hdr);
int send_http_resp_repled(struct ethhdr* eth_hdr, struct iphdr* ip_hdr, struct tcphdr* tcp_hdr,unsigned char* payload);

#endif
