#include "log.h"
#include "util.h"

static FILE *logfp;                    /* GLOBAL */
static char logbuf[MAX_BUFFER_LEN];     /* GLOBAL */

void open_log(const char *path)
{
    if(path)
    {
        logfp = open_file(path, "a");
    }
    else
    {
        logfp = open_file(DEFAULT_LOGFILE, "a");
    }

    if (logfp == NULL)
    {
        fprintf(stderr, "Open log file %s failed!\n", path);
        exit(-1);
    }
}

void close_log(void)
{
    close_file(logfp);
}

void write_log(const char* fmt, ...)
{
    time_t tt;
    struct tm local_time;
    va_list arg_ptr;
    int offset = 0;

    memset(logbuf, 0, sizeof(logbuf));
    
    time(&tt);
    /* 此处使用localtime_r 避免localtime 信号不安全问题*/
    localtime_r(&tt, &local_time);
    strftime(logbuf, sizeof(logbuf), "%Y-%m-%d %H:%M:%S ", &local_time);

    offset = strlen(logbuf);
    va_start(arg_ptr, fmt);
    vsnprintf(logbuf + offset, sizeof(logbuf) - offset, fmt, arg_ptr);
    va_end(arg_ptr); 

    /* write to the log file */
    write_file(logfp, logbuf, strlen(logbuf));
        
    fflush(logfp);
}
