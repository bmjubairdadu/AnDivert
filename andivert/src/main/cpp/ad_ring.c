/*
 * ad_ring.c — bounded FIFO of diverted packets with blocking pop.
 */

#include "ad_internal.h"
#include <string.h>
#include <stdlib.h>

void ad_ring_init(ad_ring_t *r)
{
    memset(r, 0, sizeof(*r));
    pthread_mutex_init(&r->lock, NULL);
    pthread_cond_init(&r->cond, NULL);
}

void ad_ring_destroy(ad_ring_t *r)
{
    pthread_mutex_destroy(&r->lock);
    pthread_cond_destroy(&r->cond);
}

int ad_ring_push(ad_ring_t *r, const uint8_t *data, uint32_t len,
                 const AD_ADDRESS *addr)
{
    ad_ring_item_t *slot;
    int ret = 0;

    pthread_mutex_lock(&r->lock);
    if (r->count >= AD_RING_CAPACITY) {
        ret = -1;   /* full: caller counts a lost packet */
    } else {
        slot = &r->items[r->tail];
        memcpy(slot->data, data, len);
        slot->len = len;
        slot->addr = *addr;
        slot->seq = r->next_seq++;
        r->tail = (r->tail + 1) % AD_RING_CAPACITY;
        r->count++;
        pthread_cond_signal(&r->cond);
    }
    pthread_mutex_unlock(&r->lock);
    return ret;
}

int ad_ring_pop(ad_ring_t *r, ad_ring_item_t *out, int32_t timeout_ms,
                const volatile int *closed_flag)
{
    int ret = 0;

    pthread_mutex_lock(&r->lock);
    for (;;) {
        if (r->count > 0) {
            *out = r->items[r->head];
            r->head = (r->head + 1) % AD_RING_CAPACITY;
            r->count--;
            break;
        }
        if (closed_flag && *closed_flag) {
            ret = AN_ERROR_CLOSED;
            break;
        }
        if (timeout_ms == 0) {
            ret = AN_ERROR_TIMEOUT;
            break;
        }
        if (timeout_ms < 0) {
            pthread_cond_wait(&r->cond, &r->lock);
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec  += timeout_ms / 1000;
            ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
            if (pthread_cond_timedwait(&r->cond, &r->lock, &ts) != 0) {
                if (r->count == 0) {
                    ret = (closed_flag && *closed_flag) ? AN_ERROR_CLOSED
                                                        : AN_ERROR_TIMEOUT;
                    break;
                }
            }
        }
    }
    pthread_mutex_unlock(&r->lock);
    return ret;
}

void ad_ring_wake(ad_ring_t *r)
{
    pthread_mutex_lock(&r->lock);
    pthread_cond_broadcast(&r->cond);
    pthread_mutex_unlock(&r->lock);
}
