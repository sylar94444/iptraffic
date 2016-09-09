#include "util.h"

void *alloc_buf (size_t size)
{
  void *ret;
  
  ret = malloc (size);
  if (!ret)
  {
      fprintf(stderr, "Malloc failed!\n");
        exit(-1);
  }
  
  memset (ret, 0, size);
  
  return ret;
}

void free_buf(void *p)
{
    if(p)
        free(p);
    p = NULL;
}

FILE *open_file(const char *path, const char *mode)
{
    /*************************
    FILE *fp = NULL;
    
    fp = fopen(path, mode);
    
    if (fp == NULL)
    {
        fprintf(stderr, "Open file %s failed!\n", path);
        exit(-1);
    }
        
    return fp;
    **************************/
    return fopen(path, mode);
}

void close_file(FILE *fp)
{
    if(fp)
        fclose(fp);
    fp = NULL;
}

int read_file(void*buf, size_t len, FILE *fp)
{
    size_t count = 0;    

    count = fread(buf, len, 1, fp);
    if(count < 0)
    {
        fprintf(stderr, "Read file failed!\n");
        exit(-1);        
    }

    return count;
}

int write_file(FILE *fp, void *buf, size_t len)
{
    size_t count = 0;
    
    count = fwrite(buf, len,  1, fp);
    if(count < 0)
    {
        fprintf(stderr, "Write file failed!\n");
        exit(-1);    
    }

    return count;  
}

/* 忽略掉字符换前后的空格、换行等 */
inline char *ignore_space(char *str)
{
    int len = 0;
    char *p = NULL;

    if(!str)
       return str;
    
    /* 从尾部开始搜索 */
    len = strlen(str);
    while(len > 0)
    {
        len--;
        p = str+len;
        char in = *p;
 
        if(SPACE(in))
        {
            *p = '\0';
            continue;
        }

        break;
    }
    /* 从头开始搜索 */
    len = strlen(str);
    p = str;
    while(len > 0)
    {
        char in = *p;
       
        if(SPACE(in))
        {
            len--;
            p++;
            continue;
        }

        break;
    }
   
    return p;
}

/* 将mac地址字符串转换成6字节数组 */
int mac_str_to_bin(const char *str, char *mac)
{
    int i;
    char *s, *e;

    if ((mac == NULL) || (str == NULL))
    {
        return -1;
    }

    s = (char *) str;
    for (i = 0; i < 6; ++i)
    {
        mac[i] = s ? strtoul (s, &e, 16) : 0;
        if (s)
           s = (*e) ? e + 1 : e;
    }
    return 0;
}


