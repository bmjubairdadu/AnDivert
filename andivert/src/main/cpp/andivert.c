/*
 * andivert.c — engine core: handle lifecycle, TUN read loop, dispatch.
 *
 * Data flow (mirrors WinDivert's numbered steps in the README):
 *
 *   (1) kernel writes an IP packet into the TUN fd
 *   (2) engine reads it, runs the compiled filter
 *       (2a) match  -> queued for AnDivertRecv(); the app decides
 *       (2b) nomatch-> handled by the forwarding stack (ad_forward.c),
 *                     which re-injects it towards the real network
 *   (3) AnDivertSend() writes a (possibly modified) packet back to the TUN
 *       so the kernel re-processes it, exactly like WinDivertSend.
 */

#include "ad_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* defined in ad_forward.c */
void ad_set_protect_fn(int (*fn)(int fd));

int AnDivertSetProtectFn(int (*fn)(int fd))
{
    ad_set_protect_fn(fn);
    return AN_SUCCESS;
}

static __thread int g_last_error = AN_SUCCESS;

/* ------------------------------------------------------------------ */
/* Stats helpers                                                      */
/* ------------------------------------------------------------------ */

static void ad_stat_inc(ad_handle_t *h, int which, uint64_t amount)
{
    pthread_mutex_lock(&h->stats_lock);
    switch (which) {
    case 0: h->stats.packets_divered += amount; break;
    case 1: h->stats.packets_passed   += amount; break;
    case 2: h->stats.packets_dropped  += amount; break;
    case 3: h->stats.bytes_in         += amount; break;
    case 4: h->stats.bytes_out        += amount; break;
    }
    pthread_mutex_unlock(&h->stats_lock);
}

static uint64_t ad_now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
}

/* ------------------------------------------------------------------ */
/* Read one packet from the TUN with a bounded poll                   */
/* ------------------------------------------------------------------ */

static int ad_tun_read(int fd, uint8_t *buf, uint32_t len, int timeout_ms,
                       const volatile int *running)
{
    struct pollfd pfd;
    int r;

    for (;;) {
        if (running && !*running)
            return AN_ERROR_CLOSED;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        r = poll(&pfd, 1, timeout_ms);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return AN_ERROR_IO;
        }
        if (r == 0)
            return AN_ERROR_TIMEOUT;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
            return AN_ERROR_CLOSED;
        r = (int)read(fd, buf, len);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return AN_ERROR_IO;
        }
        return r;
    }
}

/* ------------------------------------------------------------------ */
/* Engine thread                                                      */
/* ------------------------------------------------------------------ */

void *ad_engine_main(void *arg)
{
    ad_handle_t *h = (ad_handle_t *)arg;
    uint8_t *buf = (uint8_t *)malloc(AD_MAX_PACKET);
    uint64_t last_cleanup = 0;

    if (!buf) {
        ad_log_error("engine: out of memory");
        return NULL;
    }

    ad_log_info("engine started (filter=\"%s\", flags=0x%llx)",
                h->filter_expr, (unsigned long long)h->flags);

    while (h->running) {
        AD_ADDRESS addr;
        uint64_t now;
        int n;

        n = ad_tun_read(h->tun_fd, buf, AD_MAX_PACKET, 200, &h->running);
        if (n == AN_ERROR_TIMEOUT || n == AN_ERROR_CLOSED || n == AN_ERROR_IO) {
            if (!h->running)
                break;
            if (n == AN_ERROR_CLOSED) {
                ad_log_warn("engine: TUN closed unexpectedly");
                break;
            }
            if (n == AN_ERROR_IO)
                ad_log_warn("engine: TUN read error: %s", strerror(errno));
        } else if (n > 0) {
            uint32_t plen = (uint32_t)n;
            uint32_t version = buf[0] >> 4;

            /* only IPv4/IPv6 are meaningful to us */
            if (version != 4 && version != 6) {
                ad_stat_inc(h, 1, 1);   /* count as pass-through */
            } else {
                memset(&addr, 0, sizeof(addr));
                ADParsePacket(buf, plen, &addr);
                addr.timestamp_us = ad_now_us();
                addr.flags = AD_ADDRESS_FLAG_OUTBOUND;  /* from the app */
                ad_stat_inc(h, 3, plen);

                if (h->filter && ADFilterMatch(h->filter, buf, plen, &addr)) {
                    /* (2a) divert to the application */
                    if (h->flags & AN_FLAG_DROP) {
                        ad_stat_inc(h, 2, 1);
                    } else if (h->flags & AN_FLAG_SNIFF) {
                        ad_stat_inc(h, 0, 1);
                        if (ad_ring_push(&h->ring, buf, plen, &addr) != 0)
                            ad_stat_inc(h, 2, 0);
                        /* sniffing: also let it flow */
                        ad_forward_packet(h, buf, plen);
                    } else {
                        ad_stat_inc(h, 0, 1);
                        if (ad_ring_push(&h->ring, buf, plen, &addr) != 0) {
                            ad_log_warn("divert queue full, packet dropped");
                            ad_stat_inc(h, 2, 1);
                        }
                    }
                } else {
                    /* (2b) let it continue towards the real network */
                    ad_stat_inc(h, 1, 1);
                    ad_forward_packet(h, buf, plen);
                }
            }
        }

        /* periodic NAT cleanup + socket relay */
        now = ad_now_us();
        if (now - last_cleanup > 50000ull) {   /* every 50 ms */
            last_cleanup = now;
            ad_relay_poll(h, 0);
        }
    }

    free(buf);
    ad_log_info("engine stopped");
    return NULL;
}

/* Dispatch a non-diverted packet into the forwarding stack. */
void ad_forward_packet(ad_handle_t *h, const uint8_t *pkt, uint32_t len)
{
    uint8_t version;
    uint8_t proto;

    if (len < 20)
        return;
    version = pkt[0] >> 4;

    if (version == 4) {
        proto = pkt[9];
        /* never loop our own injected packets back into the forwarder */
        if (pkt[12] == 127)
            return;
    } else if (version == 6) {
        proto = pkt[6];
    } else {
        return;
    }

    switch (proto) {
    case 6:  ad_forward_tcp(h, pkt, len); break;
    case 17: ad_forward_udp(h, pkt, len); break;
    case 1:  ad_forward_icmp(h, pkt, len); break;
    default:
        /* other protocols: drop silently (no generic relay available) */
        ad_log_warn("unsupported protocol %u dropped (len=%u)", proto, len);
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

ad_handle_t *AnDivertOpen(int tun_fd, const char *filter, int layer,
                          int priority, uint64_t flags)
{
    ad_handle_t *h;
    int i;

    g_last_error = AN_SUCCESS;

    if (tun_fd < 0) {
        g_last_error = AN_ERROR_INVALID;
        return NULL;
    }

    h = (ad_handle_t *)calloc(1, sizeof(ad_handle_t));
    if (!h) {
        g_last_error = AN_ERROR_NOMEM;
        return NULL;
    }

    h->tun_fd   = tun_fd;
    h->layer    = layer;
    h->priority = priority;
    h->flags    = flags;
    h->vpn_mtu  = 1500;
    h->protect_fd = -1;
    h->running  = 1;
    h->closed   = 0;

    h->filter = ADFilterCompile(filter);
    if (!h->filter) {
        ad_log_error("filter compile failed: %s", ADFilterError());
        g_last_error = AN_ERROR_OPEN;
        free(h);
        return NULL;
    }
    snprintf(h->filter_expr, sizeof(h->filter_expr), "%s",
             (filter && filter[0]) ? filter : "true");
    ad_log_info("filter compiled: %s", h->filter_expr);

    ad_ring_init(&h->ring);
    pthread_mutex_init(&h->nat_lock, NULL);
    pthread_mutex_init(&h->stats_lock, NULL);

    for (i = 0; i < AD_MAX_UDP_FLOWS; i++) {
        h->udp_flows[i].in_use = 0;
        h->udp_flows[i].sock = -1;
    }
    for (i = 0; i < AD_MAX_TCP_CONNS; i++) {
        h->tcp_conns[i].in_use = 0;
        h->tcp_conns[i].sock = -1;
        h->tcp_conns[i].state = AD_TCP_CLOSED;
        pthread_mutex_init(&h->tcp_conns[i].lock, NULL);
    }

    if (pthread_create(&h->engine_thread, NULL, ad_engine_main, h) != 0) {
        ad_log_error("failed to start engine thread");
        g_last_error = AN_ERROR_OPEN;
        ADFilterFree(h->filter);
        ad_ring_destroy(&h->ring);
        free(h);
        return NULL;
    }

    return h;
}

int AnDivertRecv(ad_handle_t *h, void *buf, uint32_t len,
                 AD_ADDRESS *addr, uint32_t *recv_len, uint32_t timeout_ms)
{
    ad_ring_item_t item;
    int rc;

    if (!h) return AN_ERROR_INVALID;
    if (h->closed) { g_last_error = AN_ERROR_CLOSED; return AN_ERROR_CLOSED; }
    if (!buf || !recv_len) { g_last_error = AN_ERROR_INVALID; return AN_ERROR_INVALID; }

    rc = ad_ring_pop(&h->ring, &item, (int32_t)timeout_ms, &h->closed);
    if (rc != AN_SUCCESS) {
        g_last_error = rc;
        return rc;
    }
    if (item.len > len) {
        g_last_error = AN_ERROR_NOBUF;
        return AN_ERROR_NOBUF;
    }
    memcpy(buf, item.data, item.len);
    *recv_len = item.len;
    if (addr)
        *addr = item.addr;
    return AN_SUCCESS;
}

int AnDivertSend(ad_handle_t *h, const void *buf, uint32_t len,
                 const AD_ADDRESS *addr, uint32_t *send_len)
{
    ssize_t n;

    if (!h) return AN_ERROR_INVALID;
    if (h->closed) { g_last_error = AN_ERROR_CLOSED; return AN_ERROR_CLOSED; }
    if (!buf || len == 0 || len > AD_MAX_PACKET) {
        g_last_error = AN_ERROR_INVALID;
        return AN_ERROR_INVALID;
    }

    n = write(h->tun_fd, buf, len);
    if (n < 0) {
        g_last_error = AN_ERROR_IO;
        ad_log_warn("AnDivertSend failed: %s", strerror(errno));
        return AN_ERROR_IO;
    }
    ad_stat_inc(h, 4, (uint64_t)n);
    if (send_len)
        *send_len = (uint32_t)n;
    (void)addr;
    return AN_SUCCESS;
}

int AnDivertClose(ad_handle_t *h)
{
    int i;

    if (!h) return AN_ERROR_INVALID;

    h->running = 0;
    h->closed  = 1;
    ad_ring_wake(&h->ring);

    if (h->engine_thread)
        pthread_join(h->engine_thread, NULL);

    ADFilterFree(h->filter);

    pthread_mutex_lock(&h->nat_lock);
    for (i = 0; i < AD_MAX_UDP_FLOWS; i++) {
        if (h->udp_flows[i].sock >= 0)
            close(h->udp_flows[i].sock);
    }
    for (i = 0; i < AD_MAX_TCP_CONNS; i++) {
        if (h->tcp_conns[i].sock >= 0)
            close(h->tcp_conns[i].sock);
        pthread_mutex_destroy(&h->tcp_conns[i].lock);
    }
    pthread_mutex_unlock(&h->nat_lock);

    ad_ring_destroy(&h->ring);
    pthread_mutex_destroy(&h->nat_lock);
    pthread_mutex_destroy(&h->stats_lock);
    free(h);
    return AN_SUCCESS;
}

int AnDivertLastError(void)
{
    return g_last_error;
}

const char *AnDivertStrError(int err)
{
    switch (err) {
    case AN_SUCCESS:         return "success";
    case AN_ERROR_INVALID:   return "invalid argument";
    case AN_ERROR_OPEN:      return "cannot open filter";
    case AN_ERROR_IO:        return "I/O error";
    case AN_ERROR_NOBUF:     return "buffer too small";
    case AN_ERROR_NOTFOUND:  return "not found";
    case AN_ERROR_TIMEOUT:   return "timed out";
    case AN_ERROR_NOMEM:     return "out of memory";
    case AN_ERROR_CLOSED:    return "handle closed";
    case AN_ERROR_UNSUPPORTED: return "unsupported";
    default:                 return "unknown error";
    }
}

int AnDivertGetStats(ad_handle_t *h, AD_STATS *stats)
{
    if (!h || !stats) return AN_ERROR_INVALID;
    pthread_mutex_lock(&h->stats_lock);
    *stats = h->stats;
    pthread_mutex_unlock(&h->stats_lock);
    pthread_mutex_lock(&h->ring.lock);
    stats->queue_len = (uint32_t)h->ring.count;
    stats->queue_max = AD_RING_CAPACITY;
    pthread_mutex_unlock(&h->ring.lock);
    return AN_SUCCESS;
}
