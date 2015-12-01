#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#include "sysdef.h"
    
void init_pcap(const char *dev, const char *bpf);

void close_pcap(void);

void capture_pcap(void);

#endif
