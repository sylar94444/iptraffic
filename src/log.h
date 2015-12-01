#ifndef __LOG_H__
#define __LOG_H__

#include "sysdef.h"

/* Log buffer size */
#define MAX_BUFFER_LEN  65535
#define DEFAULT_LOGFILE "/var/log/iptraffic.log"

/*
 * Return value for iptraffic function
 */
#define IPTRAFFIC_FUNC_SUCCESS  0
#define IPTRAFFIC_FUNC_ERROR    -1

#define runlog(fmt, args...)    write_log("RUN "fmt"\n", ##args)
#define warnlog(fmt, args...)   write_log("WRN "fmt"\n", ##args)
#define errlog(fmt, args...)    write_log("ERR %s-L%d <%s> "fmt"\n", __FILE__, __LINE__, __func__, ##args)
#define dbglog(fmt, args...)    write_log("DBG %s-L%d <%s> "fmt"\n", __FILE__, __LINE__, __func__, ##args)

void open_log(const char *path);

void close_log(void);

void write_log(const char* fmt, ...);

#endif

