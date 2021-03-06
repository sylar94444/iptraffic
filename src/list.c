#include "list.h"
#include "util.h"
#include "iptraffic.h"
#ifdef ENABLE_DEBUG
#include "log.h"
#endif

/******************************************************************************
* Function   : list_init
* Description: 初始化链表
* Output     : 链表头指针
* Input      : 
* Return     : 链表头指针
* Note       :
******************************************************************************/
pNode init_list()
{
   pNode L = NULL;
    
   L = (pNode)MALLOC(Node, 1);
   if(L == NULL)
           return NULL;
    
    L->next = NULL;
    
    return L;
}

/******************************************************************************
* Function   : list_init
* Description: 初始化链表
* Output     : 链表头指针
* Input      : 
* Return     : 链表头指针
* Note       :
******************************************************************************/
pNode get_tail_list(struct list_s *l)
{
   pNode p = l;
    
    while(p)
    {
        if(p->next == NULL)
        {
            break;
        }
        p = p->next;
    }

    return p;
}

/******************************************************************************
* Function   : list_insert
* Description: 将节点node插入链表l的末端
* Output     : 链表头指针
* Input      : 链表l，节点node
* Return     : 
* Note       :
******************************************************************************/
void insert_tail_list(struct list_s *l, pNode node)
{
    pNode p = l;
    
    while(p)
    {
        if(p->next == NULL)
        {
            p->next = node;    
            break;
        }
        p = p->next;
    }
}

/******************************************************************************
* Function   : list_insert
* Description: 将节点node插入链表l的末端
* Output     : 链表头指针
* Input      : 链表l，节点node
* Return     : 
* Note       :
******************************************************************************/
void print_list_by_index(struct list_s *l)
{
    pNode p = l;
    
    while(p)
    {
#ifdef ENABLE_DEBUG
        dbglog("%s",p->index);
#endif
        p = p->next;
    }
}

/******************************************************************************
* Function   : list_insert
* Description: 将节点node插入链表l的末端
* Output     : 链表头指针
* Input      : 链表l，节点node
* Return     : 
* Note       :
******************************************************************************/
void clear_list(struct list_s *l)
{
    pNode p = l;
    pNode q = NULL;
    
    while(p)
    {
        q = p->next;

        FREE(p->index);
        FREE(p);
        p = q;
    }

    l = NULL;
}

#if 0
/******************************************************************************
* Function   : list_rebuild_by_host
* Description: 包含多个host的进行拆分，建立新的链表
* Output     : 新建的链表头指针
* Input      : 原始链表头指针
* Return     : 新建的链表头指针
* Note       :
******************************************************************************/
pNode rebuild_list_by_index(struct list_s *l)
{
    pNode new_list = NULL;
    pNode p = l;
    
    while(p)
    {
        /* 忽略percent之和为零的规则节点 */
        struct rule_entry_s *rule = (struct rule_entry_s *)p->entry;
#ifndef ENABLE_STAT_ONLY
        if((rule->percent == 0)||(rule->type==-1)||(strlen(p->index)<=0)||(strlen(rule->src_page)<=0))
#else
        if((rule->type==-1)||(strlen(p->index)<=0)||(strlen(rule->src_page)<=0))
#endif
        {
            p = p->next;
            continue;
        }

        /* 开始处理有效规则，拆分->插入新链表 */
        if(p->index && (strlen(p->index)>0))
        {
            char *index = NULL;
            char *buf = strdup(p->index);
        
            while((index=strtok(buf,"|"))!=NULL)
            {
                pNode node = NULL;
                
                node = init_list();
                node->index = strdup(index);
                node->entry = p->entry;

                if(new_list == NULL)
                    new_list = node;
                else
                    insert_tail_list(new_list, node);
                
                buf = NULL;
            }
        }
        p = p->next;
    }
    return new_list;
}

/******************************************************************************
* Function   : list_sort_by_host
* Description: 以host为关键字进行链表排序
* Output     : 
* Input      : 原始链表头指针
* Return     : 
* Note       :
******************************************************************************/
void sort_list_by_index(struct list_s *l)
{
	int i,j;
	pNode p = l;
	pNode pt = init_list();
	int count = 0;
	
	while(p != NULL)
	{
		count++;
		p = p->next;
	}
	
	for(i=0;i<count-1;i++) /* 冒泡法排序 */
	{
		p = l;
		for(j=0;j<count-i-1;j++)
		{
			if(strcmp(p->index, p->next->index)>0)
			{
				pt->index = p->index;
                pt->entry = p->entry;
    
                p->index = p->next->index;
                p->entry = p->next->entry;
    
                p->next->index = pt->index;
                p->next->entry = pt->entry;
			}
			p = p->next;
		}
	}
	clear_list(pt);
}
#endif

