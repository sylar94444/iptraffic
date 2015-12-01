#ifndef __SYSDEF_H__
#define __SYSDEF_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <pcap/bpf.h>
#include <pcap/pcap.h>
#include <libnet.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>    
#include <assert.h>
#include <time.h> 
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <regex.h>

#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>

#ifndef BOOL
#define BOOL int
#endif /* BOOL */

#ifndef TRUE
#define TRUE 1
#endif    /* TRUE */

#ifndef FALSE
#define FALSE 0
#endif    /* FALSE */

#endif
