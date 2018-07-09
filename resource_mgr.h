//
//  resource_mgr.h
//  libquic
//
//  Created by ganh on 2018/7/5.
//  Copyright © 2018年 inke. All rights reserved.
//

#ifndef resource_mgr_h
#define resource_mgr_h


#ifdef __cplusplus
extern "C" {
#endif

    int resource_mgr_create_ctxinfo(void *resoure, void (*destroy_cb)(void *));
    void *resource_mgr_reference_ctxinfo(int ctx_id);
    void resource_mgr_unreference_ctxinfo(int ctx_id);
    void resource_mgr_async_destroy_ctxinfo(int ctx_id);
    void resource_mgr_sync_destroy_ctxinfo(int ctx_id);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
template <class T>
class ref_holder {
private:
    int ctx_id = 0;
    T *resource = NULL;
public:
    ref_holder(void *id) {
        ctx_id = (int)(int64_t)id;
        resource = (T *)resource_mgr_reference_ctxinfo(ctx_id);
    }

    ref_holder(int id) {
        ctx_id = (int)id;
        resource = (T *)resource_mgr_reference_ctxinfo(ctx_id);
    }
    
    ~ref_holder() {
        resource_mgr_unreference_ctxinfo(ctx_id);
    }
    
    T *get() {
        return resource;
    }
};
#endif


#endif /* resource_mgr_h */
