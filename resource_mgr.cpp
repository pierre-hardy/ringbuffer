//
//  resource_mgr.cpp
//  libquic
//
//  Created by ganh on 2018/7/5.
//  Copyright © 2018年 inke. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "resource_mgr.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <mutex>

typedef void (*DESTROY_CB)(void *)  ;
class reaource_t
{
public:
    int ref = 0;
    int context_id = 0;
    void *resource = NULL;
    void (*destroy_cb)(void *) = NULL;
    int destroy_flag = 0;
};

static reaource_t g_ctx_info_list[200+10];
static int g_context_id = 1;
static std::mutex g_mut_lock;
static std::condition_variable g_condition;

#define SIZEOF_LIST()    (sizeof(g_ctx_info_list)/sizeof(g_ctx_info_list[0]))

static int check_handle(int ctx_id)
{
    int i;
    for(i=0; i<SIZEOF_LIST(); i++)
    {
        if(g_ctx_info_list[i].context_id == ctx_id)
        return i;
    }
    return -1;
}

int resource_mgr_create_ctxinfo(void *resource, void (*destroy_cb)(void *))
{
    int i, ret = 0;
    if(!resource)
        return 0;
    std::unique_lock<std::mutex> lock(g_mut_lock);
    
    for(i=0; i<SIZEOF_LIST(); i++)
    {
        if(g_ctx_info_list[i].context_id == 0)
        {
            g_ctx_info_list[i].ref++;
            g_ctx_info_list[i].resource = resource;
            g_ctx_info_list[i].destroy_cb = destroy_cb;
            g_ctx_info_list[i].context_id = g_context_id;
            g_context_id++;
            if(g_context_id > 1000000)
                g_context_id = 1;
            ret = g_ctx_info_list[i].context_id;
            return ret;
        }
    }
    printf("create_ctx_info cannot find a ctxinfo, list is full==============================\n");
    return 0;
}

void *resource_mgr_reference_ctxinfo(int ctx_id)
{
    std::unique_lock<std::mutex> lock(g_mut_lock);
    int handle;
    if((handle = check_handle(ctx_id)) >= 0)
    {
        reaource_t *ret = &(g_ctx_info_list[handle]);
        g_ctx_info_list[handle].ref++;
        return ret->resource;
    }
    return NULL;
}

static void unreference_ctxinfo_list_check_destroy_flag(int ctx_id, int destroy_flag, int sync_flag)
{
    int handle;
    DESTROY_CB cb = NULL; //cb's invocation cannot be locked by g_mut_lock.
    void *resource = NULL;
    {
        std::unique_lock<std::mutex> lock(g_mut_lock);
        if((handle = check_handle(ctx_id)) >= 0)
        {
            if(destroy_flag)
            {
                if(!g_ctx_info_list[handle].destroy_flag)
                {
                    g_ctx_info_list[handle].destroy_flag = destroy_flag;
                    if(sync_flag) {
                        while(g_ctx_info_list[handle].ref > 1) {
                            g_condition.wait(lock);
                        }
                    }
                    g_ctx_info_list[handle].ref--;
                }
                else
                {
                    return;
                }
            }
            else
            {
                if(!g_ctx_info_list[handle].destroy_flag && g_ctx_info_list[handle].ref <= 1) {
                    printf("=====================unreference_ctxinfo_list_check_destroy_flag without destroy flag but ref should be bigger than one!! ctxid = %d\n", ctx_id);
                    return;
                }
                g_ctx_info_list[handle].ref--;
            }
        }
        else
        {
            printf("=====================unreference_ctxinfo_list_check_destroy_flag not found ctx_id = %d\n", ctx_id);
            return;
        }
        if(g_ctx_info_list[handle].ref < 0)
        {
            printf("=====================unreference_ctxinfo_list_check_destroy_flag abort\n");
            abort();
        }
        // ref != 0表示当前ctxinfo正在使用，无法释放
        if(g_ctx_info_list[handle].ref == 0)
        {
            cb = g_ctx_info_list[handle].destroy_cb;
            resource = g_ctx_info_list[handle].resource;
            g_ctx_info_list[handle].resource = NULL;
            g_ctx_info_list[handle].context_id = 0;
        }
        g_condition.notify_all();
    }
    if(cb)
        cb(resource);
}

void resource_mgr_unreference_ctxinfo(int ctx_id)
{
    unreference_ctxinfo_list_check_destroy_flag(ctx_id, 0, 0);
}

void resource_mgr_async_destroy_ctxinfo(int ctx_id)
{
    unreference_ctxinfo_list_check_destroy_flag(ctx_id, 1, 0);
}

void resource_mgr_sync_destroy_ctxinfo(int ctx_id)
{
    unreference_ctxinfo_list_check_destroy_flag(ctx_id, 1, 1);
}
