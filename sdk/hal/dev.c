#include "typesdef.h"
#include "list.h"
#include "errno.h"
#include "dev.h"
#include "osal/mutex.h"
#include "osal/sleep.h"

struct dev_mgr {
    struct dev_obj  *next;
    struct os_mutex  mutex;
};

__bobj static struct dev_mgr s_dev_mgr;

__init int32 dev_init()
{
    os_mutex_init(&s_dev_mgr.mutex);
    s_dev_mgr.next = NULL;
    return RET_OK;
}

struct dev_obj *dev_get(int32 dev_id)
{
    struct dev_obj *dev = NULL;

    os_mutex_lock(&s_dev_mgr.mutex, OS_MUTEX_WAIT_FOREVER);
    dev = s_dev_mgr.next;
    while (dev) {
        if (dev->dev_id == dev_id) {
            break;
        }
        dev = dev->next;
    }
    os_mutex_unlock(&s_dev_mgr.mutex);
    return dev;
}

__init int32 dev_register(uint32 dev_id, struct dev_obj *device)
{
    hgprintf("Register DEV ID: %u", dev_id);
    struct dev_obj *dev = dev_get(dev_id);
    if (dev) {
        return -EEXIST;
    }
    device->dev_id = dev_id;
    os_mutex_lock(&s_dev_mgr.mutex, OS_MUTEX_WAIT_FOREVER);
    device->next   = s_dev_mgr.next;
    s_dev_mgr.next = device;
    os_mutex_unlock(&s_dev_mgr.mutex);
    return RET_OK;
}

#ifdef CONFIG_SLEEP
__weak int32 dev_suspend_hook(struct dev_obj *dev, uint16 type)
{
    return 1;
}
int32 dev_suspend(uint16 type)
{
    struct dev_obj *dev = NULL;

    os_mutex_lock(&s_dev_mgr.mutex, OS_MUTEX_WAIT_FOREVER);
    dev = s_dev_mgr.next;
    while (dev) {
        if (dev->ops && dev->ops->suspend) {
            if (dev_suspend_hook(dev, type)) {
                dev->ops->suspend(dev);
            }
        }
        dev = dev->next;
    }
    os_mutex_unlock(&s_dev_mgr.mutex);
    return RET_OK;
}

__weak int32 dev_resume_hook(struct dev_obj *dev, uint16 type, uint32 wkreason)
{
    return 1;
}
int32 dev_resume(uint16 type, uint32 wkreason)
{
    struct dev_obj *dev = NULL;

    os_mutex_lock(&s_dev_mgr.mutex, OS_MUTEX_WAIT_FOREVER);
    dev = s_dev_mgr.next;
    while (dev) {
        if (dev->ops && dev->ops->resume) {
            if (dev_resume_hook(dev, type, wkreason)) {
                dev->ops->resume(dev);
            }
        }
        dev = dev->next;
    }
    os_mutex_unlock(&s_dev_mgr.mutex);
    return RET_OK;
}
#endif

